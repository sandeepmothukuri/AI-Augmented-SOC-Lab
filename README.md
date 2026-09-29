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
> A comprehensive, production-grade Security Operations Center (SOC) engineering laboratory integrating **Wazuh SIEM/EDR**, **TheHive 5 Incident Management**, **Cortex Observable Analysis**, **Shuffle SOAR Workflow Orchestration**, **MISP Threat Intelligence**, and an air-gapped **Local LLM AI Engine (Ollama + LangChain + FastAPI)** for analyst-assisted alert triage, automated correlation, and playbook generation.

---

## 📑 Table of Contents

- [🎯 Project Overview & Core Mission](#-project-overview--core-mission)
- [📐 Enterprise SOC Architecture & Data Flow](#-enterprise-soc-architecture--data-flow)
- [🧩 Technology Stack & Component Matrix](#-technology-stack--component-matrix)
- [💻 Comprehensive Installation & Deployment Guide](#-comprehensive-installation--deployment-guide)
  - [System Sizing & Hardware Prerequisites](#system-sizing--hardware-prerequisites)
  - [Host Kernel & Operating System Preparation](#host-kernel--operating-system-preparation)
  - [Step 1: Clone Repository & Initialize Docker Network](#step-1-clone-repository--initialize-docker-network)
  - [Step 2: Automated Multi-Tier Stack Deployment](#step-2-automated-multi-tier-stack-deployment)
  - [Step 3: Ollama Local LLM Configuration & Hardware Tuning](#step-3-ollama-local-llm-configuration--hardware-tuning)
  - [Step 4: Platform Integrations, API Keys & Webhooks](#step-4-platform-integrations-api-keys--webhooks)
  - [Step 5: Onboarding Endpoints (Linux & Windows Agents)](#step-5-onboarding-endpoints-linux--windows-agents)
  - [Step 6: End-to-End Pipeline Health Verification](#step-6-end-to-end-pipeline-health-verification)
- [📸 Demonstrated Topics & Visual Evidence (10 Modules)](#-demonstrated-topics--visual-evidence-10-modules)
  - [Module 01: Wazuh Security Operations & Compliance Overview](#module-01-wazuh-security-operations--compliance-overview)
  - [Module 02: Wazuh Endpoint Security, FIM & Host Telemetry](#module-02-wazuh-endpoint-security-fim--host-telemetry)
  - [Module 03: Wazuh Detection Engineering & Threat Intelligence Correlation](#module-03-wazuh-detection-engineering--threat-intelligence-correlation)
  - [Module 04: TheHive 5 Incident Response & Structured Case Management](#module-04-thehive-5-incident-response--structured-case-management)
  - [Module 05: TheHive SOC Alert Queue Management & Triage](#module-05-thehive-soc-alert-queue-management--triage)
  - [Module 06: TheHive + Cortex Observable Analysis & Active Response](#module-06-thehive--cortex-observable-analysis--active-response)
  - [Module 07: Shuffle SOAR Visual Workflow Orchestration](#module-07-shuffle-soar-visual-workflow-orchestration)
  - [Module 08: MISP Threat Intelligence Platform & IOC Repository](#module-08-misp-threat-intelligence-platform--ioc-repository)
  - [Module 09: MISP Real-Time Threat Clustering & Trending Indicators](#module-09-misp-real-time-threat-clustering--trending-indicators)
  - [Module 10: Ollama & Open WebUI Private LLM Security Assistant](#module-10-ollama--open-webui-private-llm-security-assistant)
- [🤖 AI Engine Architecture & Fail-Closed Guardrails](#-ai-engine-architecture--fail-closed-guardrails)
  - [FastAPI Microservice Specification](#fastapi-microservice-specification)
  - [Prompt Engineering Framework](#prompt-engineering-framework)
  - [Deterministic Pydantic Contracts & Fail-Closed Logic](#deterministic-pydantic-contracts--fail-closed-logic)
- [🧪 End-to-End Attack Simulation & Detection Scenarios](#-end-to-end-attack-simulation--detection-scenarios)
- [🛡️ Detection Rules as Code & MITRE ATT&CK Mapping](#️-detection-rules-as-code--mitre-attck-mapping)
- [📋 SOC Analyst Incident Response Runbook](#-soc-analyst-incident-response-runbook)
- [🔧 Troubleshooting & Operational Runbook](#-troubleshooting--operational-runbook)
- [🧪 CI/CD, Code Quality & Security Auditing](#-cicd-code-quality--security-auditing)
- [👤 Author & Portfolio](#-author--portfolio)

---

## 🎯 Project Overview & Core Mission

Modern enterprise Security Operations Centers are overwhelmed by massive telemetry volumes, high false-positive ratios, fragmented tooling, and manual swivel-chair analysis. 

This repository provides a **fully operational, self-contained, enterprise-grade SOC laboratory** designed to prove how open-source detection, enrichment, orchestration, and local AI inference work together in harmony.

### Key Engineering Principles:
1. **Defense-in-Depth Telemetry**: Ingest host logs, audit events, process creation trees, File Integrity Monitoring (FIM), system calls, and network metadata.
2. **Deterministic Detection & Correlation**: Leverage Wazuh rules engine with custom XML detections mapped directly to MITRE ATT&CK techniques.
3. **Automated SOAR Orchestration**: Utilize Shuffle SOAR to intercept alerts, perform automated enrichment against threat intelligence sources, and route tasks without human intervention.
4. **Local, Air-Gapped AI Assistance**: Deploy private LLMs (Ollama LLaMA 3 / Mistral) entirely within the lab environment. No internal telemetry, IP addresses, credentials, or sensitive data ever leave your infrastructure.
5. **Fail-Closed Safety Contract**: The AI engine acts as an advisor, not an autonomous authority. All LLM outputs are validated against strict JSON schemas. If an LLM response is malformed, uncertain, or hallucinated, the pipeline **fails closed to `ENRICH`**, mandating human Tier 2 / Tier 3 analyst oversight.
6. **Standardized Incident Response**: Push high-confidence incidents into TheHive 5 with pre-configured playbooks covering Containment, Forensics, Eradication, and Recovery.

---

## 📐 Enterprise SOC Architecture & Data Flow

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

| Platform / Tool | Container / Service | Port(s) | Default Auth | Operational Function |
|---|---|---|---|---|
| **Wazuh Manager** | `wazuh-manager` | `1514` (Agents), `1515` (Reg), `514/udp` (Syslog), `55000` (API) | `admin` / `SecretPassword` | Central SIEM engine, rule evaluator, agent manager, active response |
| **Wazuh Indexer** | `wazuh-indexer` | `9200` | `admin` / `SecretPassword` | High-performance OpenSearch backend storing security event indexes |
| **Wazuh Dashboard** | `wazuh-dashboard` | `443` (mapped from 5601) | `admin` / `SecretPassword` | Visual SOC interface, IT hygiene, compliance and analytics |
| **TheHive** | `thehive` | `9000` | `admin@thehive.local` / `secret` | Security Incident Response Platform (SIRP) & case management |
| **Cortex** | `cortex` | `9001` | Initial setup screen | Observable analysis engine (VirusTotal, AbuseIPDB, URLscan, etc.) |
| **Cassandra** | `cassandra` | Internal (`9042`) | N/A | Distributed database supporting TheHive 5 cluster state |
| **Elasticsearch** | `elasticsearch` | Internal (`9200`) | N/A | Document search and indexing backend for TheHive 5 and Cortex |
| **Shuffle Frontend** | `shuffle-frontend` | `3001` (HTTP), `3443` (HTTPS) | `admin` / `password` | Visual drag-and-drop SOAR automation workflow canvas |
| **Shuffle Backend** | `shuffle-backend` | `5001` | API Key: `mysupersecretkey` | Workflow execution engine, webhook listener, app runner |
| **Shuffle OpenSearch**| `opensearch` | `9202` | N/A | Logging and workflow execution history storage for Shuffle |
| **Shuffle Database** | `shuffle-database` | `8000` | N/A | Cloud Datastore emulator supporting Shuffle configuration |
| **MISP Core** | `misp` | `8080` (HTTP), `8443` (HTTPS) | `admin@admin.test` / `admin` | Malware Information Sharing Platform, threat feeds, IOC repo |
| **MISP DB & Cache** | `misp-db`, `misp-redis` | Internal (`3306`, `6379`) | `misp` / `misp_password` | Relational storage and cache supporting MISP |
| **Ollama** | `ollama` | `11434` | Open API | Air-gapped local LLM inference server (LLaMA 3, Mistral, Phi-3) |
| **AI SOC Engine** | `ai-engine` | `8888` | Open API / CORS | FastAPI microservice with LangChain for structured alert triage |

---

## 💻 Comprehensive Installation & Deployment Guide

This section provides verified, step-by-step installation instructions for Linux (Ubuntu 20.04/22.04 LTS), WSL2 on Windows, and native Windows PowerShell with Docker Desktop.

### System Sizing & Hardware Prerequisites

| Specification | Minimum (Core Lab) | Recommended (Full AI Stack) | Enterprise / Production Grade |
|---|---|---|---|
| **CPU Cores** | 4 Physical Cores | 8 Cores (AVX2 supported) | 16+ Cores |
| **Memory (RAM)** | 16 GB | 32 GB | 64 GB+ |
| **Storage** | 100 GB SSD | 200 GB NVMe SSD | 500 GB+ NVMe SSD |
| **GPU (Optional)** | None (CPU inference) | NVIDIA GPU (8GB+ VRAM) | NVIDIA RTX 4090 / A100 |
| **Supported OS** | Ubuntu 22.04 LTS / WSL2 | Ubuntu 22.04 LTS / Win 11 WSL2 | RedHat Enterprise Linux 9 / Ubuntu |

---

### Host Kernel & Operating System Preparation

Elasticsearch, OpenSearch, and Wazuh Indexer require elevated virtual memory map counts. Failure to configure this will result in containers exiting immediately with code `137`.

#### Linux & WSL2:
```bash
# Update OS packages
sudo apt update && sudo apt upgrade -y

# Install Docker engine and Compose plugin
curl -fsSL https://get.docker.com | bash
sudo usermod -aG docker $USER

# Set mandatory kernel parameter for Elasticsearch / OpenSearch
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Apply group membership without logging out
newgrp docker
```

#### Windows (PowerShell as Administrator):
When using Docker Desktop with WSL2 backend:
```powershell
# Set kernel memory mapping on WSL2 engine
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```
To persist this across Windows reboots, create or edit `%USERPROFILE%\.wslconfig`:
```ini
[wsl2]
kernelCommandLine = "sysctl.vm.max_map_count=262144"
```

---

### Step 1: Clone Repository & Initialize Docker Network

```bash
git clone https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab.git
cd AI-Augmented-SOC-Lab
```

Create the external bridge network required by all Docker Compose stacks:
```bash
docker network create soc-network
```

> [!NOTE]
> All services communicate over the `soc-network` bridge. Creating this network beforehand ensures inter-container DNS resolution (`http://wazuh-manager`, `http://thehive`, `http://shuffle-backend`, `http://ai-engine`, `http://ollama`).

---

### Step 2: Automated Multi-Tier Stack Deployment

The laboratory can be launched either as a **unified all-in-one stack** (single command) or deployed **tier-by-tier** for resource-constrained systems.

#### Option A: Unified All-in-One Deployment (Recommended)
Launch all 17 services across all 5 tiers using the master root `docker-compose.yml`:

```bash
# Optional: customize ports and secrets
cp .env.example .env

# Deploy the entire SOC lab in the background
docker compose up -d
```

#### Option B: Automated Scripted Deployment
- **On Linux / WSL2**:
  ```bash
  chmod +x scripts/*.sh
  ./scripts/deploy.sh
  ```
- **On Windows (PowerShell as Administrator)**:
  ```powershell
  .\scripts\deploy.ps1
  ```

#### Option C: Tiered Deployment (For Systems with <= 16 GB RAM)
To deploy individual tiers sequentially and manage memory consumption:
```bash
# Tier 1: Deploy Wazuh SIEM
docker compose -f docker/docker-compose.wazuh.yml up -d
sleep 15

# Tier 2: Deploy TheHive 5 & Cortex
docker compose -f docker/docker-compose.thehive.yml up -d
sleep 10

# Tier 3: Deploy Shuffle SOAR
docker compose -f docker/docker-compose.shuffle.yml up -d

# Tier 4: Deploy MISP Threat Intelligence
docker compose -f docker/docker-compose.misp.yml up -d

# Tier 5: Deploy Ollama & AI SOC Engine
docker compose -f docker/docker-compose.ollama.yml up -d
```

---

### Step 3: Ollama Local LLM Configuration & Hardware Tuning

Download and configure your preferred open-weight model based on available host memory:

```bash
# Linux / WSL2 automated pull script:
./scripts/setup-ollama.sh llama3

# Cross-platform direct Docker commands:
# For systems with 16 GB RAM (Balanced accuracy and speed):
docker exec -it ollama ollama pull llama3

# For systems with 8 GB RAM (Fast and lightweight):
docker exec -it ollama ollama pull mistral

# For systems with 32 GB+ RAM (Maximum reasoning accuracy):
docker exec -it ollama ollama pull llama3:70b
```

Verify that Ollama responds locally:
```bash
docker exec -it ollama ollama run llama3 "Respond with: READY FOR SOC TRIAGE"
```

#### Enabling NVIDIA GPU Acceleration (Optional):
If your host has an NVIDIA GPU with the NVIDIA Container Toolkit installed, open `docker/docker-compose.ollama.yml` and uncomment lines 13-19:
```yaml
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```
Then restart Ollama: `docker compose -f docker/docker-compose.ollama.yml up -d ollama`.

---

### Step 4: Platform Integrations, API Keys & Webhooks

#### 1. Wazuh to Shuffle Webhook Integration
To stream Wazuh alerts to Shuffle SOAR automatically:
1. Open Wazuh Dashboard: `https://localhost:443` (`admin` / `SecretPassword`).
2. Open Wazuh configuration by editing `/var/ossec/etc/ossec.conf` inside the `wazuh-manager` container:
   ```bash
   docker exec -it wazuh-manager vi /var/ossec/etc/ossec.conf
   ```
3. Add the integration block before `</ossec_config>`:
   ```xml
   <integration>
     <name>custom-shuffle</name>
     <hook_url>http://shuffle-backend:5001/api/v1/hooks/YOUR_SHUFFLE_WEBHOOK_ID</hook_url>
     <level>7</level>
     <alert_format>json</alert_format>
   </integration>
   ```
4. Restart the Wazuh manager daemon:
   ```bash
   docker exec -it wazuh-manager /var/ossec/bin/wazuh-control restart
   ```

#### 2. Import Shuffle SOAR Workflows
1. Log into Shuffle UI: `http://localhost:3001` (Create initial admin user or use `admin` / `password`).
2. Navigate to **Workflows → Import Workflow**.
3. Import the pre-built workflows:
   - `shuffle-workflows/ssh-bruteforce.json`: Ingests SSH alerts, checks MISP, sends to AI Engine, notifies Slack.
   - `shuffle-workflows/malware-detection.json`: Ingests malware alerts, checks VirusTotal & MISP hashes, calls AI Engine, conditionally isolates host.
   - `shuffle-workflows/web-attack.json`: Ingests web attack alerts (SQLi, XSS, web shells), queries AbuseIPDB & MISP, triggers AI triage, applies WAF blocks, and opens structured TheHive cases.
4. Click on the **Webhook trigger node** in the imported workflow, copy the Webhook ID, and paste it into the Wazuh `hook_url`.

#### 3. Configure TheHive 5 API Key & Import Case Templates
1. Log into TheHive: `http://localhost:9000` (`admin@thehive.local` / `secret`).
2. Go to **Settings → API Keys → Create New Key**. Copy the generated key.
3. Update `docker/docker-compose.ollama.yml`:
   ```yaml
   environment:
     - THEHIVE_API_KEY=your_generated_api_key_here
     - THEHIVE_URL=http://thehive:9000
   ```
4. Restart the AI Engine container:
   ```bash
   docker compose -f docker/docker-compose.ollama.yml restart ai-engine
   ```
5. Import standard SOC case templates into TheHive:
   ```bash
   curl -X POST http://localhost:9000/api/case/template \
     -H "Authorization: Bearer YOUR_THEHIVE_API_KEY" \
     -H "Content-Type: application/json" \
     -d @thehive-config/case-templates.json
   ```

#### 4. Configure & Sync Threat Intelligence Feeds in MISP
Automatically populate MISP with curated threat intelligence feeds (Abuse.ch, URLhaus, Feodo, MalwareBazaar, CIRCL):
```bash
export MISP_URL="https://localhost"
export MISP_API_KEY="your_misp_automation_api_key"

# Enable all curated OSINT threat feeds:
python scripts/misp-feed-sync.py --enable-defaults

# Trigger immediate background sync across all enabled feeds:
python scripts/misp-feed-sync.py --sync-all

# List active feeds and caching status:
python scripts/misp-feed-sync.py --list-feeds
```

---

### Step 5: Onboarding Endpoints (Linux & Windows Agents)

#### Automated Agent Registration (Recommended):
Use the built-in registration tool to interact directly with the Wazuh REST API:
```bash
# Register a Linux server and print agent installation instructions:
python scripts/register-agent.py register --hostname web-server-01 --ip 192.168.1.50 --os linux

# Register a Windows Domain Controller into the 'servers' group:
python scripts/register-agent.py register --hostname win-dc-01 --ip 192.168.1.10 --os windows --group servers

# View all registered agents and their connection status:
python scripts/register-agent.py list
```

#### Manual Endpoint Onboarding:

#### Linux Endpoints (Debian / Ubuntu):
```bash
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_amd64.deb
sudo WAZUH_MANAGER="<WAZUH_MANAGER_IP>" dpkg -i ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

#### Linux Endpoints (CentOS / RHEL / Rocky Linux):
```bash
curl -so wazuh-agent.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.3-1.x86_64.rpm
sudo WAZUH_MANAGER="<WAZUH_MANAGER_IP>" rpm -ihv wazuh-agent.rpm
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

#### Windows Endpoints (PowerShell Administrator):
```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi" -OutFile wazuh-agent.msi
msiexec /i wazuh-agent.msi WAZUH_MANAGER="<WAZUH_MANAGER_IP>" /quiet
Start-Service -Name "WazuhSvc"
Get-Service -Name "WazuhSvc"
```

Verify that endpoints appear in the Wazuh Dashboard under **Endpoints Summary**.

---

### Step 6: End-to-End Pipeline Health Verification

Execute the health check scripts to confirm all services, ports, and container states:

```bash
# On Linux / WSL2:
./scripts/test-pipeline.sh

# On Windows PowerShell:
.\scripts\test-pipeline.ps1
```

Send a synthetic test alert to verify the AI Engine, Pydantic schema validation, and TheHive case generation:
```bash
# Test individual scenario (ssh-bruteforce, web-attack, malware, data-exfil, privilege-escalation, port-scan):
python scripts/send-test-alert.py privilege-escalation

# Or test all scenarios sequentially:
python scripts/send-test-alert.py all
```

Example output for SSH Brute Force:
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

## 📸 Demonstrated Topics & Visual Evidence (10 Modules)

This section demonstrates all 10 core operational modules of the laboratory with full technical context, architectural breakdown, and actual interface screenshots.

---

### Module 01: Wazuh Security Operations & Compliance Overview

The primary Wazuh Security Operations dashboard provides real-time visibility across enterprise compliance frameworks and IT hygiene benchmarks.

![Wazuh Security Operations Dashboard](docs/screenshots/wazuh-dashboard.png)

#### Technical Capabilities & Operational Demonstration:
- **Regulatory Framework Mapping**: Automatically maps host telemetry to **PCI DSS** (v3.2.1/4.0), **GDPR** (Articles 25, 30, 32), **HIPAA** (§164.312), **NIST SP 800-53** (Rev 5), and **Trust Services Criteria (TSC)**.
- **IT Hygiene & Misconfiguration Auditing**: Scans endpoints for exposed SSH ports, default credentials, inactive accounts, insecure daemon configurations, and legacy protocols.
- **Security Configuration Assessment (SCA)**: Continuously validates operating systems against CIS (Center for Internet Security) Benchmarks, providing pass/fail scores and remediation commands.

---

### Module 02: Wazuh Endpoint Security, FIM & Host Telemetry

Wazuh EDR agents collect deep endpoint telemetry, tracking active processes, network sockets, user logins, and system changes in real time.

![Wazuh Endpoint Security](docs/screenshots/wazuh-endpoint-security.png)

#### Technical Capabilities & Operational Demonstration:
- **File Integrity Monitoring (FIM)**: Monitors real-time cryptographic file hashes (MD5, SHA1, SHA256) across system binaries, DLLs, and configuration files. Detects permission tampering and unexpected file creations.
- **Who-Data Auditing**: Uses Linux auditd and Windows SACLs to capture the exact user ID, process ID, and parent binary responsible for modifying sensitive files.
- **Process Lineage & Anomaly Detection**: Uncovers suspicious parent-child process relationships, such as web servers (`apache2`, `nginx`, `w3wp.exe`) spawning interactive command shells (`bash`, `powershell.exe`).

---

### Module 03: Wazuh Detection Engineering & Threat Intelligence Correlation

The threat intelligence and detection view correlates raw system events against Wazuh's rules engine, applying custom XML rules and MITRE ATT&CK taxonomy.

![Wazuh Threat Intelligence](docs/screenshots/wazuh-threat-intel.png)

#### Technical Capabilities & Operational Demonstration:
- **Severity-Tiered Prioritization**: Groups alerts from Level 1 to 15, allowing SOC analysts to filter out low-level noise and immediately address Level 10+ threats.
- **Custom XML Detection Engine**: Houses detection logic in [`wazuh-config/custom-rules.xml`](wazuh-config/custom-rules.xml), detecting multi-stage brute force, sudo escalation, web shells, and ransomware extensions.
- **Dynamic Threat Intel Correlation**: Cross-references source IPs and file hashes against CDB lookup tables and internal reputation lists.

---

### Module 04: TheHive 5 Incident Response & Structured Case Management

When an alert warrants escalation, TheHive 5 creates a structured case initialized with dynamic response tasks, evidence logs, and observable tracking.

![TheHive Case Management](docs/screenshots/thehive-case-management.png)

#### Technical Capabilities & Operational Demonstration:
- **Pre-Configured Case Templates**: Automatically loads templates from [`thehive-config/case-templates.json`](thehive-config/case-templates.json) for Brute Force, Malware, and Data Exfiltration incidents.
- **Standardized Incident Response Phases**: Pre-populates actionable investigation tasks grouped into **Containment**, **Forensics & Investigation**, **Eradication**, and **Recovery**.
- **Evidence Preservation & Chain of Custody**: Links raw logs, PCAPs, memory dumps, and analyst notes with cryptographic timestamps and Traffic Light Protocol (TLP) ratings.

---

### Module 05: TheHive SOC Alert Queue Management & Triage

The incoming alert queue in TheHive acts as the primary triage console for SOC analysts, receiving normalized security events from Wazuh and Shuffle.

![TheHive Alert Management](docs/screenshots/thehive-alert-management.png)

#### Technical Capabilities & Operational Demonstration:
- **Automated Deduplication**: Deduplicates repeated alerts occurring within defined time windows to eliminate alert fatigue.
- **Observable Preview**: Extracts IPs, hostnames, user accounts, and file hashes directly into the triage view for instant evaluation.
- **One-Click Case Promotion**: Analysts can promote verified threats into active cases with complete alert context preserved, or dismiss false positives.

---

### Module 06: TheHive + Cortex Observable Analysis & Active Response

Cortex integrates directly with TheHive to execute automated observable analysis across third-party threat intelligence APIs and security tools.

![TheHive Cortex Analysis](docs/screenshots/thehive-cortex-response.png)

#### Technical Capabilities & Operational Demonstration:
- **Multi-Engine Analyzers**: Triggers parallel lookups against VirusTotal, AbuseIPDB, URLscan, Shodan, and MISP without leaving the incident interface.
- **Automated Responder Actions**: Enables analysts to initiate active response actions, such as blocking an IP on a border firewall, quarantining an email, or isolating an endpoint.
- **Report Attachment**: Automatically embeds structured JSON reports and reputation scores directly into the case timeline.

---

### Module 07: Shuffle SOAR Visual Workflow Orchestration

Shuffle SOAR connects SIEM alerts, enrichment tools, AI engines, and ticketing systems into cohesive, automated playbooks.

![Shuffle SOAR Workflow](docs/screenshots/shuffle-workflow.png)

#### Detailed Workflow Breakdown:
```text
┌─────────────────────────┐
│  Wazuh Webhook Ingestion│
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Parse Alert Attributes  │ (Extracts srcip, rule_id, hostname, SHA256)
└────────────┬────────────┘
             │
             ├─────────────────────────────────────────┐
             ▼                                         ▼
┌─────────────────────────┐               ┌─────────────────────────┐
│   MISP Threat Search    │               │  VirusTotal / URLscan   │
└────────────┬────────────┘               └────────────┬────────────┘
             │                                         │
             └────────────────────┬────────────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │ AI Engine /analyze API  │ (Ollama LLaMA 3 Triage)
                     └────────────┬────────────┘
                                  │
                     ┌────────────┴────────────┐
                     ▼                         ▼
             [Verdict == ESCALATE]     [Verdict == CLOSE]
                     │                         │
                     ▼                         ▼
        ┌─────────────────────────┐   ┌─────────────────────────┐
        │  TheHive Case Creation  │   │     Log and Archive     │
        └────────────┬────────────┘   └─────────────────────────┘
                     │
                     ▼
        ┌─────────────────────────┐
        │ Slack / Discord Alert   │
        └─────────────────────────┘
```

---

### Module 08: MISP Threat Intelligence Platform & IOC Repository

MISP serves as the central Threat Intelligence Platform (CTI) for storing, correlating, and sharing Indicators of Compromise.

![MISP Threat Intelligence Dashboard](docs/screenshots/misp-dashboard.png)

#### Technical Capabilities & Operational Demonstration:
- **Automated Threat Feeds**: Synchronizes with global OSINT feeds (abuse.ch URLhaus, MalwareBazaar, CIRCL, AlienVault OTX).
- **Taxonomy & Tagging**: Automatically annotates indicators with confidence scores, adversary attribution, and MITRE ATT&CK techniques.
- **Bi-Directional Correlation**: Automatically correlates internal IOCs detected by Wazuh against globally observed threat campaigns.

---

### Module 09: MISP Real-Time Threat Clustering & Trending Indicators

MISP’s analytics engine aggregates newly observed indicators into trending threat clusters, identifying emerging malware waves and C2 infrastructure.

![MISP Trending Indicators](docs/screenshots/misp-trendings.png)

#### Technical Capabilities & Operational Demonstration:
- **Trending Threat Identification**: Highlights surging malware variants and active infrastructure before enterprise perimeters are targeted.
- **Cluster Visualization**: Exposes relationships between IP subnets, domain registration patterns, and malware hashes.
- **Automated SIEM Export**: Exports high-confidence indicators directly into Wazuh lookup lists to block malicious traffic at the agent level.

---

### Module 10: Ollama & Open WebUI Private LLM Security Assistant

Open WebUI provides an interactive, private interface for SOC analysts to query local Ollama models, analyze malicious scripts, and generate hunting queries.

![Ollama Open WebUI](docs/screenshots/ollama-openwebui.png)

#### Technical Capabilities & Operational Demonstration:
- **100% On-Premise Privacy**: Guarantees zero sensitive data leakage; prompts and telemetry are processed entirely within your infrastructure.
- **Script De-Obfuscation**: Assists analysts in decoding obfuscated PowerShell commands, base64 payloads, and malicious shell scripts.
- **Natural Language to Elasticsearch DSL**: Converts English questions (e.g., *"Show failed SSH logins from external IPs in the past 24 hours"*) into valid Elasticsearch DSL queries.

---

## 🤖 AI Engine Architecture & Fail-Closed Guardrails

The AI SOC Engine (`ai-engine/`) is an asynchronous microservice written in **Python 3.11**, **FastAPI**, and **LangChain**.

### FastAPI Microservice Specification

```text
ai-engine/
├── app.py                # FastAPI endpoints, CORS, background task dispatching
├── analyzer.py           # Core triage chains, Pydantic contracts, MITRE mapper
├── thehive_client.py     # Asynchronous client for automated case generation
├── requirements.txt      # Dependency specification
├── knowledge_base/       # Grounded SOC IR runbooks (brute force, ransomware, web, etc.)
│   ├── brute_force.json
│   ├── malware_ransomware.json
│   ├── web_attack.json
│   ├── data_exfiltration.json
│   └── privilege_escalation.json
└── prompts/
    ├── triage.txt        # Strict classification prompt (ESCALATE|CLOSE|ENRICH)
    ├── summary.txt       # Technical 2-3 sentence incident briefing
    ├── playbook.txt      # Numbered incident response playbook
    └── nl_to_dsl.txt     # English to Elasticsearch DSL translator
```

#### Key API Endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Reports service status and active Ollama model name |
| `POST` | `/analyze` | Ingests `AlertPayload`, executes triage chains, returns validated `TriageResult` |
| `POST` | `/playbook` | Generates a 5-10 step incident response procedure for a given attack type |
| `POST` | `/query` | Translates natural-language questions into Elasticsearch DSL JSON |
| `GET` | `/stats` | Returns real-time metrics (analyzed, escalated, closed, error counts) |

---

### Prompt Engineering Framework

The engine utilizes four prompt templates in `ai-engine/prompts/`, engineered for determinism:
- **Temperature Setting**: Explicitly set to `0.1` across all chains to eliminate creative hallucinations and enforce consistency.
- **Strict Format Enclosure**: Prompts enforce JSON-only outputs, instructing the model to reject conversational pleasantries.
- **False-Positive Bias**: Instructs the model to evaluate whether the alert matches known internal scanners (e.g., Nessus, Qualys) before escalating.

---

### Deterministic Pydantic Contracts & Fail-Closed Logic

Model outputs are parsed using non-greedy JSON decoding and strictly validated against Pydantic models:

```python
class TriageDecision(BaseModel):
    verdict: str = Field(pattern=r"^(CLOSE|ESCALATE|ENRICH)$")
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str = Field(pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    reasoning: str = Field(min_length=1, max_length=4000)
```

> [!CAUTION]
> **The Fail-Closed Security Policy**:
> If the local LLM generates invalid JSON, unexpected keys, or unsupported verdicts, the analyzer catches the `ValidationError` and **fails closed**:
> ```python
> return {
>     "verdict": "ENRICH",
>     "confidence": 0.5,
>     "severity": "MEDIUM",
>     "reasoning": "LLM output did not satisfy the triage contract; manual enrichment required.",
> }
> ```
> This ensures no alert is ever silently discarded or improperly handled due to AI failure.

---

## 🧪 End-to-End Attack Simulation & Detection Scenarios

The repository includes both quick test scripts (`scripts/send-test-alert.py`) and an **advanced adversary emulation runner** (`scripts/simulate-attacks.py`) that can transmit synthetic alerts directly to the AI Engine and over live **UDP Syslog (port 514)** to Wazuh Manager:

```bash
# Execute advanced adversary simulation runner (All 8 Scenarios):
python scripts/simulate-attacks.py all

# Run specific attack scenario:
python scripts/simulate-attacks.py ssh-bruteforce
python scripts/simulate-attacks.py web-shell
python scripts/simulate-attacks.py ransomware-fim

# Stream live UDP Syslog into Wazuh Manager while analyzing:
python scripts/simulate-attacks.py all --syslog --wazuh-host localhost --wazuh-port 514
```

### Complete Multi-Stage Scenario Matrix:

| ID | Attack Technique | Simulated Telemetry / Indicator | Wazuh Rule | ATT&CK Mapping | Expected Disposition |
|---|---|---|---|---|---|
| **SOC-001** | SSH Brute Force & Success | 200 failed auths + 1 accepted login for root | `5712`, `100001` | Credential Access (`T1110`) | `ESCALATE` (Critical) |
| **SOC-002** | External Port Scan | 2000 SYN packets across ports within 30s | `ET-SCAN-001` | Discovery (`T1046`) | `ESCALATE` (High) |
| **SOC-003** | Web SQL Injection | `UNION SELECT` injection via POST `/login` | `31103` | Initial Access (`T1190`) | `ESCALATE` (High) |
| **SOC-004** | Web Shell Execution | Command execution via PHP upload (`whoami`) | `100003` | Persistence (`T1505.003`) | `ESCALATE` (Critical) |
| **SOC-005** | Unauthorized Sudo Abuse | User not in sudoers executing `/bin/bash` | `100002` | Privilege Escalation (`T1068`) | `ESCALATE` (High) |
| **SOC-006** | Ransomware Mass Encryption | 64 file extensions modified to `.encrypted` | `553`, `100006` | Impact (`T1486`) | `ESCALATE` (Critical) |
| **SOC-007** | DNS Tunneling Exfiltration | 4500 high-entropy DNS queries / hour | `100008` | Exfiltration (`T1071.004`) | `ENRICH` / `ESCALATE` |
| **SOC-008** | Windows Pass-the-Hash | NTLM LogonType 3 from non-domain workstation | `100007` | Lateral Movement (`T1550.002`) | `ESCALATE` (High) |

---

## 🛡️ Detection Rules as Code & Endpoint Telemetry Templates

Custom detection rules and auditing configurations are version-controlled in [`wazuh-config/`](wazuh-config/):

### Custom Wazuh XML Detection Rules (`wazuh-config/custom-rules.xml`):

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

### Hardened Endpoint Auditing Templates:
- [`wazuh-config/ossec.conf`](wazuh-config/ossec.conf): Reference Wazuh Manager configuration with Shuffle webhook `<integration>` and automated `<active-response>` definitions (`firewall-drop`).
- [`wazuh-config/sysmonconfig.xml`](wazuh-config/sysmonconfig.xml): Production-ready Sysmon configuration auditing process trees (Event ID 1), outbound socket connections (Event ID 3), DLL injection (Event ID 7/8), and ransomware file extensions (Event ID 11).
- [`wazuh-config/audit.rules`](wazuh-config/audit.rules): Linux audit daemon rules tracking `execve` system calls, `/etc/sudoers` modifications, and user identity changes.

---

## 📋 SOC Analyst Incident Response Runbook

When an incident is escalated into TheHive 5, analysts adhere to the following workflow:

```text
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌─────────────┐     ┌───────────┐
│  1. TRIAGE  │ ──► │ 2. ENRICH    │ ──► │ 3. INVESTIGATE│ ──► │ 4. CONTAIN  │ ──► │ 5. RECOVER│
└─────────────┘     └──────────────┘     └───────────────┘     └─────────────┘     └───────────┘
```

1. **Phase 1: Triage & Verification**:
   - Verify alert source, timestamp, hostname, and user context.
   - Review the AI Engine's summary and confidence score. Do not accept AI verdicts blindly.
   - Verify whether the activity matches authorized penetration testing or scheduled administrative tasks.
2. **Phase 2: Enrichment**:
   - Query Cortex analyzers for IP reputation (AbuseIPDB) and file hashes (VirusTotal).
   - Check MISP for matching threat actor campaigns or malware families.
3. **Phase 3: Investigation & Scoping**:
   - Query Wazuh SIEM logs across adjacent endpoints for lateral movement indicators.
   - Map confirmed adversary behavior to the MITRE ATT&CK framework.
4. **Phase 4: Containment**:
   - Isolate the affected host via Wazuh Active Response (`firewall-drop` or host isolation).
   - Revoke compromised user credentials and invalidate active session tokens.
5. **Phase 5: Eradication & Recovery**:
   - Terminate malicious processes and remove persistence mechanisms (cron jobs, registry keys).
   - Restore affected systems from verified, clean backups.
   - Document lessons learned and update Wazuh detection rules to prevent recurrence.

---

## 🔧 Troubleshooting & Operational Runbook

### 1. Elasticsearch / OpenSearch Fails to Start (`exit code 137`)
- **Root Cause**: Host kernel memory map setting (`vm.max_map_count`) is too low.
- **Resolution**:
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
  ```

### 2. High Memory Usage on Systems with Limited RAM
- **Resolution**: Lower Java Heap settings in `docker-compose.thehive.yml` and `docker-compose.wazuh.yml`:
  ```yaml
  environment:
    - "ES_JAVA_OPTS=-Xms256m -Xmx512m"
    - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
  ```

### 3. Ollama Model Download Fails or Times Out
- **Resolution**: Download a smaller quantized model:
  ```bash
  docker exec -it ollama ollama pull mistral
  # or
  docker exec -it ollama ollama pull phi3
  ```
  Update `MODEL_NAME=mistral` in `docker/docker-compose.ollama.yml` and restart the AI Engine:
  ```bash
  docker compose -f docker/docker-compose.ollama.yml restart ai-engine
  ```

### 4. AI Engine Cannot Communicate with TheHive
- **Resolution**: Verify TheHive API key is generated and correctly specified in `docker-compose.ollama.yml`:
  ```bash
  docker exec -it ai-engine curl -H "Authorization: Bearer YOUR_KEY" http://thehive:9000/api/case
  ```

---

## 🧪 CI/CD, Code Quality & Security Auditing

The repository enforces enterprise-grade code quality and security standards via GitHub Actions:

- **Formatting & Style**: Validated with `black==24.10.0` and `isort`.
- **Linting**: Verified with `flake8` (`--max-line-length=100 --ignore=E501,W503`).
- **Deterministic Contract Tests**: Enforced with `pytest tests/test_analyzer_contract.py`.
- **Infrastructure as Code Validation**: Docker Compose config parsing across all YAML files.
- **Configuration Linting**: Python JSON validation for TheHive case templates and Shuffle workflows; ElementTree XML parsing for Wazuh rules.
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

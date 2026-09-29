# 🔄 Shuffle SOAR Bi-Directional Workflows

This directory contains production-ready Shuffle SOAR workflows (.json) establishing a complete closed-loop incident response system between **Wazuh SIEM**, **MISP Threat Intel**, **Local AI Engine**, and **TheHive 5 Incident Management**.

---

## 📋 Workflow Inventory

| Workflow File | Trigger Source | Integration Flow | Purpose |
|---|---|---|---|
| `wazuh-ai-thehive-pipeline.json` | Wazuh Webhook (`rule.level >= 7`) | Wazuh → MISP → AI Engine (`/analyze` + `/playbook`) → TheHive 5 | Ingests SIEM alert, extracts IOCs, looks up threat intel, triages via local LLM, and creates structured TheHive case with playbook tasks. |
| `thehive-to-wazuh-containment.json` | TheHive 5 Case Webhook (`tag: isolate-ip`) | TheHive 5 → Shuffle → Wazuh Manager (`PUT /active-response`) → TheHive 5 | **Bi-directional loop**: When an analyst tags a case or observable with `isolate-ip`, Shuffle commands Wazuh Active Response to execute `firewall-drop` and logs confirmation back to the case timeline. |
| `web-attack.json` | Wazuh Webhook (Web group rules) | Wazuh → AbuseIPDB / MISP → AI Engine → Wazuh Active Response → TheHive 5 | Auto-containment pipeline for SQL injection, XSS, and web shells. |
| `ssh-bruteforce.json` | Wazuh Webhook (SSH rules) | Wazuh → MISP → AI Engine → Slack Notification | Real-time Slack/Discord analyst notification for credential attacks. |
| `malware-detection.json` | Wazuh Webhook (Malware rules) | Wazuh → VirusTotal → MISP → AI Engine → Endpoint Isolation | Automated endpoint containment for high-confidence malware detections. |

---

## 🚀 Setup & Import Guide

### 1. Import Workflow into Shuffle
1. Log into Shuffle UI: `http://localhost:3001` (Default credentials: `admin` / `password`).
2. Click **Workflows** in the left menu → **Import Workflow**.
3. Select `shuffle-workflows/wazuh-ai-thehive-pipeline.json` or `shuffle-workflows/thehive-to-wazuh-containment.json`.
4. Click **Import**.

### 2. Configure Wazuh → Shuffle Integration
In `wazuh-config/ossec.conf` or inside the `wazuh-manager` container (`/var/ossec/etc/ossec.conf`), ensure the webhook integration is defined:
```xml
<integration>
  <name>custom-shuffle</name>
  <hook_url>http://shuffle-backend:5001/api/v1/hooks/YOUR_SHUFFLE_WEBHOOK_ID</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

### 3. Configure TheHive 5 → Shuffle Webhook
To enable bi-directional containment:
1. In TheHive 5, navigate to **Platform Management → Webhooks**.
2. Add a new outgoing webhook:
   - **Name**: `Shuffle Containment Dispatcher`
   - **Target URL**: `http://shuffle-backend:5001/api/v1/hooks/YOUR_CONTAINMENT_WEBHOOK_ID`
   - **Events**: `Case.Update`, `Case.Create`
3. Whenever an analyst adds the tag `isolate-ip` or `contain-host` to any case or observable, Shuffle immediately invokes Wazuh active-response `firewall-drop`.

# 📊 SOC KPI Executive Dashboards

This directory provides pre-configured, production-grade dashboards for monitoring Security Operations Center (SOC) efficiency, detection fidelity, and adversary activity across the **MITRE ATT&CK framework**.

---

## 📈 Tracked Metrics & Visualizations

| Visualization | Metric / Dimension | SOC Operational Value |
|---|---|---|
| **Mean Time to Detect (MTTD)** | `decoder.processing_time_ms` / time elapsed from log creation to index | Evaluates SIEM pipeline performance and latency before adversary detection. |
| **Mean Time to Acknowledge (MTTA)** | Latency between alert indexing and initial triage verdict | Measures SOC responsiveness; accelerated from minutes to milliseconds via the local AI engine. |
| **MITRE ATT&CK Matrix Distribution** | Aggregated by `rule.mitre.tactic` & `rule.mitre.id` | Highlights which adversary tactics (Credential Access, Execution, C2) are most active. |
| **Alert Fidelity Ratio** | High-severity alerts (`level >= 10`) vs routine noise (`level < 10`) | Identifies signal-to-noise ratio to prevent alert fatigue. |
| **Top Noisy Rules** | Frequency distribution by `rule.id` and `rule.description` | Pinpoints primary candidates for tuning, whitelisting, or baseline adjustment. |
| **AI Engine Triage Ratio** | `ESCALATE` vs `CLOSE` vs `ENRICH` | Demonstrates tier-1 triage reduction and automated closure efficiency. |

---

## 📥 How to Import

### 1. Wazuh Indexer / OpenSearch Dashboards (Recommended)
1. Navigate to Wazuh Dashboard: `https://localhost:443` (Default: `admin` / `SecretPassword`).
2. Open top-left menu → **Stack Management** → **Saved Objects**.
3. Click **Import** in the upper-right corner.
4. Select `dashboards/opensearch_soc_kpi_dashboard.ndjson`.
5. Check **Automatically overwrite all saved objects** and click **Import**.
6. Navigate to **Dashboards** → Select **📊 SOC Executive KPI & MITRE Operations Dashboard**.

### 2. Grafana
1. Log into Grafana (`http://localhost:3000`).
2. Go to **Dashboards** → **New** → **Import**.
3. Upload `dashboards/grafana-soc-kpi.json`.
4. Select your OpenSearch / Elasticsearch datasource (`wazuh-alerts-*`).
5. Click **Import**.

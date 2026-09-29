#!/usr/bin/env bash
# Network Attack PCAP Replay Script
# Replays curated PCAPs into the SOC lab network using tcpreplay or Python generator
set -euo pipefail

INTERFACE="${1:-eth0}"
SCENARIO="${2:-all}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PCAP_DIR="${REPO_ROOT}/pcaps"

echo "=========================================================="
echo "▶ Network Sensor Telemetry Replayer"
echo "  Target Interface: ${INTERFACE}"
echo "  Scenario:         ${SCENARIO}"
echo "=========================================================="

# Ensure PCAPs exist
if [[ ! -d "${PCAP_DIR}" || -z "$(ls -A "${PCAP_DIR}" 2>/dev/null)" ]]; then
    echo "[*] Generating curated PCAP files..."
    python3 "${SCRIPT_DIR}/replay-pcap.py" --generate-all-pcaps
fi

# Check for tcpreplay
if command -v tcpreplay &>/dev/null; then
    echo "[+] Found tcpreplay binary"
    for pcap in "${PCAP_DIR}"/*.pcap; do
        if [[ -f "${pcap}" ]]; then
            echo "[+] Replaying ${pcap} onto ${INTERFACE}..."
            sudo tcpreplay --intf1="${INTERFACE}" --topspeed "${pcap}" || true
        fi
    done
else
    echo "[*] tcpreplay not installed; streaming live attack simulation via Python..."
    python3 "${SCRIPT_DIR}/replay-pcap.py" --scenario "${SCENARIO}" --live-replay
fi

echo "[✔] Network telemetry replay finished."

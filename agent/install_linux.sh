#!/usr/bin/env bash
# ==============================================================================
# SentinelDLP Enterprise Endpoint Protection Agent - Linux Automated Installer & Systemd Service
# ==============================================================================
set -e

SERVER_URL="${1:-http://127.0.0.1:8000}"
EMPLOYEE_ID="${2:-EMP-$(hostname | tr '[:lower:]' '[:upper:]')}"
CURRENT_USER="${SUDO_USER:-$USER}"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================================="
echo "   SentinelDLP Endpoint Protection Agent - Linux Installer       "
echo "================================================================="
echo "Target Central DLP Server: ${SERVER_URL}"
echo "Configured Employee ID:    ${EMPLOYEE_ID}"
echo "Running User:              ${CURRENT_USER}"
echo "Install Directory:         ${INSTALL_DIR}"
echo "-----------------------------------------------------------------"

# 1. Setup Python virtual environment
cd "${INSTALL_DIR}"
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[*] Activating virtual environment & installing agent dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

# 2. Save local environment configuration
cat <<EOF > .env
DLP_SERVER_URL="${SERVER_URL}"
EMPLOYEE_ID="${EMPLOYEE_ID}"
AGENT_SECRET="sentinel_agent_telemetry_secure_token_key_9981"
PYTHONPATH="${INSTALL_DIR}:${INSTALL_DIR}/.."
EOF

echo "[+] Local configuration saved to ${INSTALL_DIR}/.env"

# 3. Configure systemd service if running with root / sudo permissions
if [ "$EUID" -eq 0 ] || command -v sudo >/dev/null 2>&1; then
    echo "[*] Installing systemd auto-startup service (sentineldlp-agent.service)..."
    SERVICE_FILE="/etc/systemd/system/sentineldlp-agent.service"
    
    sudo bash -c "cat <<EOF > ${SERVICE_FILE}
[Unit]
Description=SentinelDLP Enterprise Endpoint Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/agent.py --server-url ${SERVER_URL} --employee-id ${EMPLOYEE_ID}
Restart=always
RestartSec=5
KillMode=process
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF"

    sudo systemctl daemon-reload
    sudo systemctl enable sentineldlp-agent.service
    echo "[+] Systemd service installed and enabled for automatic boot startup."
    echo "[+] To start service now: sudo systemctl start sentineldlp-agent.service"
    echo "[+] To view service logs: sudo journalctl -u sentineldlp-agent.service -f"
else
    echo "[!] Non-root user: Systemd service generation skipped. Run with sudo to enable auto-boot service."
fi

echo "================================================================="
echo "✅ SentinelDLP Agent installation completed successfully!"
echo "================================================================="

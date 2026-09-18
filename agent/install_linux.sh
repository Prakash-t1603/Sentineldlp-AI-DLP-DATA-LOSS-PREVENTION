#!/usr/bin/env bash
# ==============================================================================
# SentinelDLP Enterprise Endpoint Protection Agent - Linux Automated Installer
# ==============================================================================
set -e

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${INSTALL_DIR}"

CURRENT_USER="${SUDO_USER:-$USER}"

# Command line parameters with defaults
CLI_SERVER_URL="${1:-}"
CLI_EMPLOYEE_ID="${2:-}"
CLI_NAME="${3:-}"
CLI_EMAIL="${4:-}"
CLI_DEPT="${5:-}"
CLI_DESIG="${6:-}"

echo "================================================================="
echo "   🛡️ SentinelDLP Endpoint Protection Agent - Linux Installer   "
echo "================================================================="
echo "Install Directory: ${INSTALL_DIR}"
echo "Running User:      ${CURRENT_USER}"
echo "-----------------------------------------------------------------"

# Interactive prompts if running in terminal and values not fully supplied
if [ -t 0 ]; then
    echo "[?] Please provide employee & endpoint details to register in Central SOC:"
    echo ""
    
    # 1. Central DLP Server URL
    DEFAULT_SERVER="${CLI_SERVER_URL:-http://127.0.0.1:8000}"
    read -rp "Central DLP Server URL [${DEFAULT_SERVER}]: " INPUT_SERVER
    SERVER_URL="${INPUT_SERVER:-$DEFAULT_SERVER}"
    # Strip trailing slash
    SERVER_URL="${SERVER_URL%/}"

    # 2. Employee ID (Mandatory)
    DEFAULT_EMP="${CLI_EMPLOYEE_ID:-}"
    EMPLOYEE_ID=""
    while [ -z "${EMPLOYEE_ID}" ]; do
        if [ -n "${DEFAULT_EMP}" ]; then
            read -rp "Employee ID (e.g. EMP-WIN-01) [${DEFAULT_EMP}]: " INPUT_EMP
            EMPLOYEE_ID="${INPUT_EMP:-$DEFAULT_EMP}"
        else
            read -rp "Employee ID (e.g. EMP-WIN-01): " INPUT_EMP
            EMPLOYEE_ID="${INPUT_EMP}"
        fi
        if [ -z "${EMPLOYEE_ID}" ]; then
            echo "❌ An assigned Employee ID is mandatory."
        fi
    done

    # 3. Employee Full Name
    DEFAULT_NAME="${CLI_NAME:-${CURRENT_USER}}"
    read -rp "Employee Full Name [${DEFAULT_NAME}]: " INPUT_NAME
    EMPLOYEE_NAME="${INPUT_NAME:-$DEFAULT_NAME}"

    # 4. Email ID
    DEFAULT_EMAIL="${CLI_EMAIL:-${CURRENT_USER}@company.com}"
    read -rp "Corporate Email ID [${DEFAULT_EMAIL}]: " INPUT_EMAIL
    EMPLOYEE_EMAIL="${INPUT_EMAIL:-$DEFAULT_EMAIL}"

    # 5. Department
    DEFAULT_DEPT="${CLI_DEPT:-Cybersecurity}"
    read -rp "Department (e.g. Engineering, SOC, Finance) [${DEFAULT_DEPT}]: " INPUT_DEPT
    EMPLOYEE_DEPT="${INPUT_DEPT:-$DEFAULT_DEPT}"

    # 6. Designation
    DEFAULT_DESIG="${CLI_DESIG:-Security Analyst}"
    read -rp "Designation (e.g. Endpoint User, Developer, Analyst) [${DEFAULT_DESIG}]: " INPUT_DESIG
    EMPLOYEE_DESIG="${INPUT_DESIG:-$DEFAULT_DESIG}"
    echo ""
else
    if [ -z "${CLI_EMPLOYEE_ID}" ]; then
        echo "❌ ERROR: Employee ID is required!" >&2
        echo "Usage: ./install_linux.sh <SERVER_URL> <EMPLOYEE_ID> [NAME] [EMAIL] [DEPT] [DESIG]" >&2
        echo "Example: ./install_linux.sh http://172.24.143.236:8000 EMP-WIN-01" >&2
        exit 1
    fi
    SERVER_URL="${CLI_SERVER_URL:-http://127.0.0.1:8000}"
    SERVER_URL="${SERVER_URL%/}"
    EMPLOYEE_ID="${CLI_EMPLOYEE_ID}"
    EMPLOYEE_NAME="${CLI_NAME:-${CURRENT_USER}}"
    EMPLOYEE_EMAIL="${CLI_EMAIL:-${CURRENT_USER}@company.com}"
    EMPLOYEE_DEPT="${CLI_DEPT:-Engineering}"
    EMPLOYEE_DESIG="${CLI_DESIG:-Endpoint User}"
fi

echo "================================================================="
echo "   Configured Endpoint Deployment Profile:"
echo "   - Central DLP Server:  ${SERVER_URL}"
echo "   - Employee ID:         ${EMPLOYEE_ID}"
echo "   - Employee Name:       ${EMPLOYEE_NAME}"
echo "   - Email Address:       ${EMPLOYEE_EMAIL}"
echo "   - Department:          ${EMPLOYEE_DEPT}"
echo "   - Designation:         ${EMPLOYEE_DESIG}"
echo "================================================================="

# 1. Setup Python virtual environment
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[*] Activating virtual environment & installing agent dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

# 2. Fix permissions & Save local environment configuration
if [ -f ".env" ]; then
    chmod 666 .env 2>/dev/null || rm -f .env 2>/dev/null || (command -v sudo >/dev/null 2>&1 && sudo rm -f .env) || true
fi

cat <<EOF > .env
DLP_SERVER_URL="${SERVER_URL}"
SERVER_URL="${SERVER_URL}"
EMPLOYEE_ID="${EMPLOYEE_ID}"
EMPLOYEE_NAME="${EMPLOYEE_NAME}"
EMPLOYEE_EMAIL="${EMPLOYEE_EMAIL}"
EMPLOYEE_DEPT="${EMPLOYEE_DEPT}"
EMPLOYEE_DESIG="${EMPLOYEE_DESIG}"
AGENT_SECRET="sentinel_agent_telemetry_secure_token_key_9981"
PYTHONPATH="${INSTALL_DIR}:${INSTALL_DIR}/.."
EOF

chmod 664 .env 2>/dev/null || true
echo "[+] Local configuration saved to ${INSTALL_DIR}/.env"

# Save persistent employee id file
echo "${EMPLOYEE_ID}" > .employee_id 2>/dev/null || true

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
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/agent.py --server-url ${SERVER_URL} --employee-id ${EMPLOYEE_ID} --name \"${EMPLOYEE_NAME}\" --email \"${EMPLOYEE_EMAIL}\" --dept \"${EMPLOYEE_DEPT}\" --desig \"${EMPLOYEE_DESIG}\"
Restart=always
RestartSec=5
KillMode=process
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF"

    sudo systemctl daemon-reload 2>/dev/null || true
    sudo systemctl enable sentineldlp-agent.service 2>/dev/null || true
    echo "[+] Systemd service registered for automatic boot startup."
else
    echo "[!] Non-root user: Systemd service setup skipped."
fi

echo "================================================================="
echo "✅ SentinelDLP Agent installation completed successfully!"
echo "================================================================="
echo ""
echo "To start the agent manually right now, run:"
echo "  source ${INSTALL_DIR}/venv/bin/activate"
echo "  python ${INSTALL_DIR}/agent.py --server-url \"${SERVER_URL}\" --employee-id \"${EMPLOYEE_ID}\" --name \"${EMPLOYEE_NAME}\" --email \"${EMPLOYEE_EMAIL}\" --dept \"${EMPLOYEE_DEPT}\" --desig \"${EMPLOYEE_DESIG}\""
echo ""
echo "Or start via systemd service:"
echo "  sudo systemctl restart sentineldlp-agent.service"
echo "  sudo journalctl -u sentineldlp-agent.service -f"
echo "================================================================="

#!/usr/bin/env bash
# ==============================================================================
# SentinelDLP Enterprise Endpoint Protection Agent - macOS Automated Installer & Launchd Service
# ==============================================================================
set -e

SERVER_URL="${1:-http://127.0.0.1:8000}"
EMPLOYEE_ID="${2:-EMP-$(scutil --get ComputerName 2>/dev/null || hostname | tr '[:lower:]' '[:upper:]')}"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================================="
echo "   SentinelDLP Endpoint Protection Agent - macOS Installer       "
echo "================================================================="
echo "Target Central DLP Server: ${SERVER_URL}"
echo "Configured Employee ID:    ${EMPLOYEE_ID}"
echo "Install Directory:         ${INSTALL_DIR}"
echo "-----------------------------------------------------------------"

# 1. Setup Python virtual environment
cd "${INSTALL_DIR}"
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "[*] Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

# 2. Save local environment configuration
cat <<EOF > .env
DLP_SERVER_URL="${SERVER_URL}"
EMPLOYEE_ID="${EMPLOYEE_ID}"
AGENT_SECRET="sentinel_agent_telemetry_secure_token_key_9981"
PYTHONPATH="${INSTALL_DIR}"
EOF

# 3. Configure launchd agent for automatic startup
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
mkdir -p "$LAUNCH_AGENTS_DIR"
PLIST_FILE="$LAUNCH_AGENTS_DIR/com.sentineldlp.agent.plist"

cat <<EOF > "${PLIST_FILE}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentineldlp.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/venv/bin/python</string>
        <string>${INSTALL_DIR}/agent.py</string>
        <string>--server-url</string>
        <string>${SERVER_URL}</string>
        <string>--employee-id</string>
        <string>${EMPLOYEE_ID}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${INSTALL_DIR}/logs/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${INSTALL_DIR}/logs/agent_error.log</string>
</dict>
</plist>
EOF

launchctl unload "${PLIST_FILE}" 2>/dev/null || true
launchctl load "${PLIST_FILE}"
echo "[+] macOS launchd service loaded and configured for automatic startup on user login."

echo "================================================================="
echo "✅ SentinelDLP macOS Agent installed and active!"
echo "================================================================="

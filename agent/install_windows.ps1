# ==============================================================================
# SentinelDLP Enterprise Endpoint Protection Agent - Windows Auto-Startup Installer
# ==============================================================================
param (
    [string]$ServerUrl = "http://127.0.0.1:8000",
    [string]$EmployeeId = "EMP-$env:COMPUTERNAME"
)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   SentinelDLP Endpoint Protection Agent - Windows Installer    " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Target Central DLP Server: $ServerUrl" -ForegroundColor Yellow
Write-Host "Configured Employee ID:    $EmployeeId" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------"

$AgentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# 1. Setup virtual environment
Set-Location -Path $AgentDir
if (-Not (Test-Path -Path "$AgentDir\venv")) {
    Write-Host "[*] Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv "$AgentDir\venv"
}

Write-Host "[*] Installing endpoint agent dependencies..." -ForegroundColor Yellow
& "$AgentDir\venv\Scripts\pip.exe" install --upgrade pip -q
& "$AgentDir\venv\Scripts\pip.exe" install -r "$AgentDir\requirements.txt" -q

# 2. Save local environment configuration
@"
DLP_SERVER_URL=$ServerUrl
EMPLOYEE_ID=$EmployeeId
AGENT_SECRET=sentinel_agent_telemetry_secure_token_key_9981
PYTHONPATH=$AgentDir
"@ | Out-File -FilePath "$AgentDir\.env" -Encoding utf8

Write-Host "[+] Local environment configuration saved to $AgentDir\.env" -ForegroundColor Green

# 3. Configure Windows Auto-Startup via Task Scheduler (Runs automatically at system startup)
$TaskName = "SentinelDLPEndpointAgent"
$PythonExe = "$AgentDir\venv\Scripts\pythonw.exe"
if (-Not (Test-Path -Path $PythonExe)) {
    $PythonExe = "$AgentDir\venv\Scripts\python.exe"
}
$Arguments = "`"$AgentDir\agent.py`" --server-url `"$ServerUrl`" --employee-id `"$EmployeeId`""

try {
    # Check if task already exists
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    
    $Action = New-ScheduledTaskAction -Execute $PythonExe -Argument $Arguments -WorkingDirectory $AgentDir
    $Trigger = New-ScheduledTaskTrigger -AtLogon
    $Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "SentinelDLP Enterprise Endpoint Monitoring Agent"
    Write-Host "[+] Windows Scheduled Task '$TaskName' registered successfully for automatic startup on logon." -ForegroundColor Green
} catch {
    Write-Host "[!] Note: Could not register Windows Scheduled Task: $_. Falling back to Startup folder shortcut." -ForegroundColor Yellow
    $WshShell = New-Object -ComObject WScript.Shell
    $StartupDir = [Environment]::GetFolderPath("Startup")
    $Shortcut = $WshShell.CreateShortcut("$StartupDir\SentinelDLPAgent.lnk")
    $Shortcut.TargetPath = $PythonExe
    $Shortcut.Arguments = $Arguments
    $Shortcut.WorkingDirectory = $AgentDir
    $Shortcut.WindowStyle = 7 # Minimized
    $Shortcut.Save()
    Write-Host "[+] Created Startup folder shortcut at $StartupDir\SentinelDLPAgent.lnk" -ForegroundColor Green
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "✅ SentinelDLP Windows Agent installed and configured for auto-startup!" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan

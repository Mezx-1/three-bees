# WOLVE endpoint agent installer (Windows, per user).
#   powershell -ExecutionPolicy Bypass -File agent\install_agent.ps1 [-Server http://host:8000] [-EnrolAs aisha.admin] [-AllowResponse]
#   powershell -ExecutionPolicy Bypass -File agent\install_agent.ps1 -Uninstall
param(
    [string]$Server = "http://localhost:8000",
    [string]$EnrolAs = "aisha.admin",
    [switch]$AllowResponse,
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$TaskName = "WOLVE Agent"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "WOLVE agent startup task removed."
    } else {
        Write-Host "WOLVE agent startup task was not installed."
    }
    exit 0
}

Write-Host ""
Write-Host "WOLVE endpoint agent will monitor on this computer:" -ForegroundColor Cyan
Write-Host "  - network connections (program, remote address, port) - never the content"
Write-Host "  - new suspicious processes (e.g. Office launching PowerShell)"
Write-Host "  - Windows Firewall and Defender status (read-only)"
Write-Host "It does NOT record screens, keystrokes, calls, files, browsing or passwords."
if ($AllowResponse) { Write-Host "  - analysts may block IP addresses in Windows Firewall on this computer" -ForegroundColor Yellow }
$answer = Read-Host "Does the user of this computer agree? (yes/no)"
if ($answer -ne "yes") { Write-Host "Installation cancelled - no consent."; exit 1 }

$venv = Join-Path $Here ".venv"
$py = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "Creating agent environment..."
    python -m venv $venv
    & $py -m pip install --quiet --upgrade pip
}
& $py -m pip install --quiet -r (Join-Path $Here "requirements.txt")

$agent = Join-Path $Here "wolve_agent.py"
if (-not (Test-Path (Join-Path $Here ".wolve_agent.json"))) {
    & $py $agent --server $Server --enrol-as $EnrolAs --consent
}

$args = "`"$agent`" --monitor"
if ($AllowResponse) { $args += " --allow-response" }
$action = New-ScheduledTaskAction -Execute $py -Argument $args -WorkingDirectory $Here
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$runLevel = if ($AllowResponse) { "Highest" } else { "Limited" }
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel $runLevel
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "WOLVE agent installed and started. It runs (visibly) at every sign-in. Remove with -Uninstall." -ForegroundColor Green

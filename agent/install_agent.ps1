# WOLVE endpoint agent installer (Windows, current user).
#
#   Preview only (changes nothing):  powershell -ExecutionPolicy Bypass -File agent\install_agent.ps1 -DryRun
#   Install:                         powershell -ExecutionPolicy Bypass -File agent\install_agent.ps1 [-Server http://host:8000] -PairCode ABCD2345
#   Install with firewall response:  (run PowerShell as Administrator) ... -AllowResponse
#   Remove startup task:             powershell -ExecutionPolicy Bypass -File agent\install_agent.ps1 -Uninstall [-Purge]
param(
    [string]$Server = "http://localhost:8000",
    [string]$PairCode = "",
    [switch]$AllowResponse,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$DryRun
)
$ErrorActionPreference = "Stop"
$TaskName = "WOLVE Agent"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $Here ".venv"
$Py = Join-Path $Venv "Scripts\python.exe"
$Agent = Join-Path $Here "wolve_agent.py"
$StateFile = Join-Path $Here ".wolve_agent.json"

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Assert-Ok($what) {
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE). Nothing was registered for startup." }
}

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    } else {
        Write-Host "Scheduled task '$TaskName' was not installed."
    }
    if ($Purge) {
        if (Test-Path $StateFile) { Remove-Item $StateFile -Force; Write-Host "Deleted device token file." }
        if (Test-Path $Venv) { Remove-Item $Venv -Recurse -Force; Write-Host "Deleted agent environment." }
    }
    Write-Host "Note: WOLVE firewall rules (named WOLVE-block-*) are not removed automatically. List them with:"
    Write-Host "  Get-NetFirewallRule -DisplayName 'WOLVE-block-*'"
    exit 0
}

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "This installer will make these changes:" -ForegroundColor Cyan
Write-Host "  1. Create a Python environment in $Venv and install psutil"
Write-Host "  2. Enrol this computer with the WOLVE server $Server (saves a device token in $StateFile)"
if ($existing) { Write-Host "  3. REPLACE the existing scheduled task '$TaskName' (no duplicate is created)" }
else { Write-Host "  3. Create the scheduled task '$TaskName' that starts the agent (in a visible window) when $env:USERNAME signs in" }
Write-Host ""
Write-Host "The agent will monitor:" -ForegroundColor Cyan
Write-Host "  - network connections: program, remote address and port (never the content)"
Write-Host "  - suspicious new processes (e.g. Office starting PowerShell)"
Write-Host "  - Windows Firewall and Defender status (read-only)"
Write-Host "It does NOT record screens, keystrokes, calls, files, browsing or passwords."
if ($AllowResponse) {
    Write-Host "  - analysts may BLOCK IP addresses in Windows Firewall (rules named WOLVE-block-<ip>); the task runs with highest privileges" -ForegroundColor Yellow
}
Write-Host "Undo at any time with:  install_agent.ps1 -Uninstall -Purge"
Write-Host ""

if ($DryRun) { Write-Host "Dry run: nothing was changed."; exit 0 }
if ($AllowResponse -and -not (Test-Admin)) {
    Write-Host "-AllowResponse needs an elevated PowerShell (Run as administrator). Nothing was changed." -ForegroundColor Red
    exit 1
}
$answer = Read-Host "Does the user of this computer agree to these changes and to monitoring? Type 'yes' to continue"
if ($answer -ne "yes") { Write-Host "Installation cancelled - no consent. Nothing was changed."; exit 1 }

try {
    if (-not (Test-Path $Py)) {
        Write-Host "Creating agent environment..."
        python -m venv $Venv; Assert-Ok "Creating the Python environment (is Python 3.10+ installed and on PATH?)"
    }
    & $Py -m pip install --quiet -r (Join-Path $Here "requirements.txt"); Assert-Ok "Installing psutil"
    if (-not (Test-Path $StateFile)) {
        if (-not $PairCode) { throw "A pairing code is required: WOLVE web app -> Settings -> Pair a device -> Code for a laptop agent, then pass -PairCode CODE" }
        & $Py $Agent --server $Server --pair $PairCode --consent; Assert-Ok "Enrolling with the WOLVE server"
    }
    $taskArgs = "`"$Agent`" --monitor"
    if ($AllowResponse) { $taskArgs += " --allow-response" }
    $action = New-ScheduledTaskAction -Execute $Py -Argument $taskArgs -WorkingDirectory $Here
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $runLevel = if ($AllowResponse) { "Highest" } else { "Limited" }
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel $runLevel
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $taskSettings -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "WOLVE agent installed and started. It runs visibly at every sign-in. Remove with -Uninstall." -ForegroundColor Green
} catch {
    Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

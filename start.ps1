# WOLVE AI — one-command local start (Windows PowerShell).
# First run installs dependencies; later runs just start both servers.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$py = Join-Path $root "backend\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "Creating Python virtual environment..."
    python -m venv (Join-Path $root "backend\.venv")
    & $py -m pip install --upgrade pip
    & $py -m pip install -r (Join-Path $root "backend\requirements.txt")
}
if (-not (Test-Path (Join-Path $root "frontend\node_modules"))) {
    Write-Host "Installing frontend dependencies..."
    npm --prefix (Join-Path $root "frontend") install
}

Write-Host "Starting backend on http://localhost:8000 ..."
Start-Process -FilePath $py -ArgumentList "-m","uvicorn","--app-dir",(Join-Path $root "backend"),"app.main:app","--host","127.0.0.1","--port","8000" -WorkingDirectory $root
Write-Host "Starting frontend on http://localhost:3000 ..."
Start-Process -FilePath "npm.cmd" -ArgumentList "--prefix",(Join-Path $root "frontend"),"run","dev","--","-p","3000" -WorkingDirectory $root
Start-Sleep -Seconds 6
Start-Process "http://localhost:3000"

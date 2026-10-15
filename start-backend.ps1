# Starts the Craxis backend on Windows.
# Usage: powershell -ExecutionPolicy Bypass -File start-backend.ps1 [-Intel]
param(
    [switch]$Intel
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3.10+ is required. Install it from https://www.python.org/downloads/"
}

python -c "import flask, sklearn, joblib, flask_cors, pandas, numpy" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing Python dependencies..."
    python -m pip install -r ml/requirements.txt
}

if ($Intel) {
    $env:AIPHISH_ENABLE_INTEL = "1"
    Write-Host "Domain intelligence lookups are ENABLED (hostnames are sent to public registries)."
}

Write-Host "Starting backend on http://127.0.0.1:5000 (Ctrl+C to stop)"
python ml/app.py

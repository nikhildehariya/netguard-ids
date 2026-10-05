# run-netguard.ps1
# Unified launcher for NetGuard IDS v2.1

$ErrorActionPreference = "Stop"

Write-Host "🛡️  Starting NetGuard IDS Launcher..." -ForegroundColor Cyan

# ── Prerequisite Checks ───────────────────────────────────────
Write-Host "`n[1] Checking prerequisites..." -ForegroundColor Yellow

if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed or not in your PATH. Please install Python 3.11+."
}
if (-not (Get-Command "node" -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js is not installed or not in your PATH. Please install Node.js 18+."
}

# ── Python Venv Setup ─────────────────────────────────────────
Write-Host "`n[2] Setting up virtual environment..." -ForegroundColor Yellow
if (-not (Test-Path "venv")) {
    Write-Host "Virtual environment not found. Creating..." -ForegroundColor DarkYellow
    python -m venv venv
    & .\venv\Scripts\pip.exe install -r requirements.txt
}

# ── React Node Modules Setup ──────────────────────────────────
Write-Host "`n[3] Setting up React dashboard dependencies..." -ForegroundColor Yellow
if (-not (Test-Path "react-dashboard\node_modules")) {
    Write-Host "node_modules not found. Running npm install..." -ForegroundColor DarkYellow
    Push-Location react-dashboard
    npm install
    Pop-Location
}

# ── Start Services ────────────────────────────────────────────
$ApiPort = 8081

if (Test-Path ".env") {
    $EnvFile = Get-Content ".env"
    foreach ($line in $EnvFile) {
        if ($line -match "^API_PORT=(.*)$") {
            $ApiPort = [int]$Matches[1].Trim()
        }
    }
}

$BackendRunning = $false
try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$ApiPort/health" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
    if ($resp.StatusCode -eq 200) {
        $BackendRunning = $true
    }
} catch {}

$BackendProcess = $null
if ($BackendRunning) {
    Write-Host "`n[4] Backend API is already running on port $ApiPort. Bypassing startup." -ForegroundColor Green
} else {
    Write-Host "`n[4] Starting FastAPI backend on port $ApiPort..." -ForegroundColor Yellow
    $BackendProcess = Start-Process -FilePath "venv\Scripts\python.exe" -ArgumentList "-m uvicorn api.main:app --host 0.0.0.0 --port $ApiPort" -PassThru -NoNewWindow

}

Write-Host "[5] Starting React dashboard on port 5174..." -ForegroundColor Yellow
Push-Location react-dashboard
$FrontendProcess = Start-Process -FilePath "npm.cmd" -ArgumentList "run dev" -PassThru -NoNewWindow
Pop-Location

# ── Open Web Browser ──────────────────────────────────────────
Write-Host "`n[6] Waiting for services to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host "Opening dashboard in your web browser..." -ForegroundColor Green
Start-Process "http://localhost:5174"

# ── Process Monitoring Loop ───────────────────────────────────
Write-Host "`n=======================================================" -ForegroundColor Cyan
Write-Host "NetGuard IDS is running!" -ForegroundColor Green
Write-Host "- API Server: http://127.0.0.1:$ApiPort" -ForegroundColor Gray
Write-Host "- Web Panel:  http://localhost:5174" -ForegroundColor Gray
Write-Host "Press Ctrl+C or close this window to stop both servers." -ForegroundColor Yellow
Write-Host "=======================================================" -ForegroundColor Cyan


try {
    while ($true) {
        # Check if backend or frontend died
        if ($BackendProcess -and $BackendProcess.HasExited) {
            Write-Host "`n[!] Backend API server stopped unexpectedly." -ForegroundColor Red
            break
        }
        if ($FrontendProcess.HasExited) {
            Write-Host "`n[!] React dashboard server stopped unexpectedly." -ForegroundColor Red
            break
        }
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host "`nStopping NetGuard services..." -ForegroundColor Yellow
    if ($BackendProcess -and -not $BackendProcess.HasExited) {
        Stop-Process -Id $BackendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($FrontendProcess -and -not $FrontendProcess.HasExited) {
        Stop-Process -Id $FrontendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Done. Goodbye!" -ForegroundColor Green
}

# Quickstart script for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "🛡️  Aginiti Red-Team: 1-Minute Automated Assessment Demo" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. API Keys Check
if (Test-Path .env) {
    Get-Content .env | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim(" `"'")
            [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
        }
    }
}

if (-not $env:GROQ_API_KEY -and -not $env:OPENAI_API_KEY -and -not $env:GEMINI_API_KEY -and -not $env:ANTHROPIC_API_KEY) {
    Write-Host "`n⚠️  No LLM API Key detected in environment or .env file." -ForegroundColor Yellow
    Write-Host "Aginiti needs at least one API key to plan campaigns and judge results.`n" -ForegroundColor Yellow
    
    $groqKey = Read-Host "Enter your GROQ_API_KEY (Recommended, or press Enter to skip)"
    $openaiKey = Read-Host "Enter your OPENAI_API_KEY (or press Enter to skip)"
    $geminiKey = Read-Host "Enter your GEMINI_API_KEY (or press Enter to skip)"
    
    if ($groqKey) { Add-Content -Path .env -Value "GROQ_API_KEY=""$groqKey""" }
    if ($openaiKey) { Add-Content -Path .env -Value "OPENAI_API_KEY=""$openaiKey""" }
    if ($geminiKey) { Add-Content -Path .env -Value "GEMINI_API_KEY=""$geminiKey""" }
    
    if (Test-Path .env) {
        Get-Content .env | ForEach-Object {
            if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
                $key = $matches[1].Trim()
                $val = $matches[2].Trim(" `"'")
                [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
            }
        }
    }
}

# 2. Virtual Environment & Install
if (-not (Test-Path .venv)) {
    Write-Host "`n[1/4] Creating virtual environment (.venv)..." -ForegroundColor Green
    python -m venv .venv
}

$venvPython = Join-Path (Get-Location) ".venv\Scripts\python.exe"
$venvPip = Join-Path (Get-Location) ".venv\Scripts\pip.exe"

Write-Host "[2/4] Installing / Verifying Aginiti Red-Team & Demo Target..." -ForegroundColor Green
Write-Host "      (First-time run downloads ~150MB of wheel dependencies; please wait...)" -ForegroundColor DarkGray
& $venvPython -m pip install --prefer-binary --upgrade pip

if (Test-Path pyproject.toml) {
    & $venvPython -m pip install --prefer-binary -e ".[demo-target]"
} else {
    & $venvPython -m pip install --prefer-binary "aginiti-redteam[demo-target]"
}

# Pre-seed ChromaDB vector store & download ONNX embeddings ahead of time
Write-Host "      (Verifying local vector database & ONNX embedding models...)" -ForegroundColor DarkGray
& $venvPython -m aginiti.demo_target.seed 2>&1 | Out-Null

# 3. Port Selection (Check if port 8001 is already in use)
$port = 8001

# Guard against an orphaned demo target from a PREVIOUS run of this same
# script left behind on this machine (e.g. the terminal window was closed
# before the `finally` block below got a chance to run, so its
# `aginiti.demo_target.main` child was never stopped and just kept
# listening). Safe unconditionally: only matches our own module
# invocation, never an unrelated process.
Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*aginiti.demo_target.main*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

function Test-PortInUse([int]$p) {
    # 1. Check if connecting succeeds
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect("127.0.0.1", $p, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne(300, $false)
        if ($wait -and $tcpClient.Connected) {
            $tcpClient.EndConnect($asyncResult)
            $tcpClient.Close()
            return $true # Port is in use
        }
        $tcpClient.Close()
    } catch {}

    # 2. Check if we can bind
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $p)
        $listener.Start()
        $listener.Stop()
        return $false # Free to bind
    } catch {
        return $true # Port in use / cannot bind
    }
}

if (Test-PortInUse $port) {
    Write-Host "`n⚠️  Port $port is already in use by another process." -ForegroundColor Yellow
    $userPort = Read-Host "Enter a different port to use [default: 8010]"
    if ($userPort) { $port = [int]$userPort } else { $port = 8010 }

    while (Test-PortInUse $port) {
        Write-Host "⚠️  Port $port is also in use." -ForegroundColor Yellow
        $userPort = Read-Host "Please enter an open port [e.g. 8020]"
        if ($userPort) { $port = [int]$userPort } else { $port = 8020 }
    }
}

# 4. Start Demo Target in Background
Write-Host "`n[3/4] Launching Hardened Target Agent on port $port..." -ForegroundColor Green
$targetProcess = Start-Process -FilePath $venvPython -ArgumentList "-u -m aginiti.demo_target.main --port $port --hardened" -PassThru -NoNewWindow

try {
    Write-Host "Waiting for target agent to initialize on http://localhost:$port..." -ForegroundColor DarkGray
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $resp = Invoke-RestMethod -Uri "http://localhost:$port/health" -Method Get -TimeoutSec 2 -ErrorAction Stop
            $ready = $true
            break
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    
    if (-not $ready) {
        throw "Target server failed to start on port $port. Check target_server.log for details."
    }

    # /health responding is necessary but not sufficient -- confirm it's
    # actually OUR process that answered, not something else that grabbed
    # the port in the gap between the check above and this script's own
    # start. A dead $targetProcess with a live /health response would
    # otherwise silently point the scan at the wrong target.
    $targetProcess.Refresh()
    if ($targetProcess.HasExited) {
        throw "Something else is already answering on port $port -- it did not come from this script's own server (PID $($targetProcess.Id) exited). Re-run and choose a different port when prompted, or free port $port and try again."
    }

    Write-Host "✅ Target is live on http://localhost:$port`n" -ForegroundColor Green
    
    # 5. Run Full Assessment Scan
    Write-Host "[4/4] Starting Full Assessment Campaign (50 queries across all 47 operators)..." -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    
    $venvAginiti = Join-Path (Get-Location) ".venv\Scripts\aginiti.exe"
    if (Test-Path $venvAginiti) {
        & $venvAginiti scan --target "http://localhost:$port" --tier full_assessment --budget 50
    } else {
        & $venvPython -m aginiti.cli scan --target "http://localhost:$port" --tier full_assessment --budget 50
    }
}
finally {
    Write-Host "`n🛑 Shutting down demo target agent..." -ForegroundColor Yellow
    if ($targetProcess -and -not $targetProcess.HasExited) {
        Stop-Process -Id $targetProcess.Id -Force
    }
}

Write-Host "`n🎉 Assessment complete! Interactive HTML report generated in results/ directory." -ForegroundColor Green

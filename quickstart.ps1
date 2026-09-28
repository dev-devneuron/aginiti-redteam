# Quickstart script for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "🛡️  Aginiti Red-Team: 1-Minute Automated Assessment Demo" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. API Keys Check
function Import-DotEnv {
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

function Test-LlmConfigured {
    return [bool]($env:GROQ_API_KEY -or $env:OPENAI_API_KEY -or $env:GEMINI_API_KEY -or $env:ANTHROPIC_API_KEY -or $env:AGINITI_LLM_MODEL)
}

Import-DotEnv

if (-not (Test-LlmConfigured)) {
    Write-Host "`n⚠️  No LLM API Key detected in environment or .env file." -ForegroundColor Yellow
    Write-Host "Aginiti needs at least one API key to plan campaigns and judge results.`n" -ForegroundColor Yellow

    $groqKey = Read-Host "Enter your GROQ_API_KEY (Recommended, or press Enter to skip)"
    $openaiKey = Read-Host "Enter your OPENAI_API_KEY (or press Enter to skip)"
    $geminiKey = Read-Host "Enter your GEMINI_API_KEY (or press Enter to skip)"

    if ($groqKey) { Add-Content -Path .env -Value "GROQ_API_KEY=""$groqKey""" }
    if ($openaiKey) { Add-Content -Path .env -Value "OPENAI_API_KEY=""$openaiKey""" }
    if ($geminiKey) { Add-Content -Path .env -Value "GEMINI_API_KEY=""$geminiKey""" }

    # Any other provider LiteLLM supports, routed via AGINITI_LLM_MODEL /
    # AGINITI_LLM_API_KEY (see aginiti/providers/llm.py). When set, it is
    # the model Aginiti uses, ahead of the keys above.
    Write-Host "`nUsing a different LLM provider? Enter it as LiteLLM's provider/model name, for example:" -ForegroundColor Cyan
    Write-Host "    anthropic/claude-3-5-haiku-latest" -ForegroundColor DarkGray
    Write-Host "    deepseek/deepseek-chat" -ForegroundColor DarkGray
    Write-Host "    mistral/mistral-small-latest" -ForegroundColor DarkGray
    Write-Host "    openrouter/meta-llama/llama-3.1-70b-instruct" -ForegroundColor DarkGray
    Write-Host "  (full list: https://docs.litellm.ai/docs/providers)" -ForegroundColor DarkGray
    while ($true) {
        $customModel = (Read-Host "Provider/model (or press Enter to skip)").Trim()
        if (-not $customModel -or $customModel -match '^[A-Za-z0-9_.-]+/\S+$') { break }
        Write-Host "⚠️  '$customModel' is not in provider/model form (e.g. deepseek/deepseek-chat). Try again." -ForegroundColor Yellow
    }
    if ($customModel) {
        $customProvider = $customModel.Split("/")[0]
        $customKey = Read-Host "Enter your API key for $customProvider (or press Enter if it needs none, e.g. ollama)"
        Add-Content -Path .env -Value "AGINITI_LLM_MODEL=""$customModel"""
        if ($customKey) { Add-Content -Path .env -Value "AGINITI_LLM_API_KEY=""$customKey""" }
    }

    Import-DotEnv

    if (-not (Test-LlmConfigured)) {
        throw "No LLM API key provided. Set one in the environment or in .env and re-run."
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

# Confirm the configured LLM actually answers before starting a long scan:
# a wrong key or a mistyped provider/model name otherwise surfaces only as
# every judge call failing, deep into the run.
Write-Host "      (Checking LLM access...)" -ForegroundColor DarkGray
$llmCheck = @'
import sys
from aginiti.providers.llm import active_provider_name, chat
name = active_provider_name()
try:
    chat([{'role': 'user', 'content': 'Reply with the word OK.'}], max_tokens=256)
except Exception as exc:
    print('LLM check failed for ' + name + ': ' + type(exc).__name__ + ': ' + str(exc)[:400])
    sys.exit(1)
print('      LLM reachable: ' + name)
'@
& $venvPython -c $llmCheck
if ($LASTEXITCODE -ne 0) {
    throw "Could not reach the configured LLM. Check the API key and provider/model name in .env, then re-run."
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

# Always address the target as 127.0.0.1, never "localhost". The server binds
# 0.0.0.0 (IPv4 only), but Windows resolves "localhost" to ::1 first and
# retries the refused IPv6 connection for ~2s before falling back to IPv4.
# That stall exceeds a short health-check timeout (so every probe fails and
# the script gives up on a perfectly healthy server), and it adds ~2s to
# every single request the scan sends.
$targetUrl = "http://127.0.0.1:$port"

try {
    Write-Host "Waiting for target agent to initialize on $targetUrl..." -ForegroundColor DarkGray
    $ready = $false
    for ($i = 0; $i -lt 90; $i++) {
        # Fail fast if the server process died (import error, port clash,
        # seeding failure) instead of polling a dead process for minutes.
        $targetProcess.Refresh()
        if ($targetProcess.HasExited) {
            throw "Target server exited during startup (exit code $($targetProcess.ExitCode)). See its output above for the error."
        }
        try {
            $resp = Invoke-RestMethod -Uri "$targetUrl/health" -Method Get -TimeoutSec 5 -ErrorAction Stop
            $ready = $true
            break
        } catch {
            Start-Sleep -Seconds 1
        }
    }

    if (-not $ready) {
        throw "Target server did not answer $targetUrl/health within 90 seconds. See its output above for details."
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

    Write-Host "✅ Target is live on $targetUrl`n" -ForegroundColor Green
    
    # 5. Run Full Assessment Scan
    Write-Host "[4/4] Starting Full Assessment Campaign (50 queries across all 47 operators)..." -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    
    $venvAginiti = Join-Path (Get-Location) ".venv\Scripts\aginiti.exe"
    if (Test-Path $venvAginiti) {
        & $venvAginiti scan --target $targetUrl --tier full_assessment --budget 50
    } else {
        & $venvPython -m aginiti.cli scan --target $targetUrl --tier full_assessment --budget 50
    }
    # Native commands don't honor $ErrorActionPreference in Windows PowerShell 5.1.
    if ($LASTEXITCODE -ne 0) {
        throw "Assessment scan failed (exit code $LASTEXITCODE). See its output above."
    }
}
finally {
    Write-Host "`n🛑 Shutting down demo target agent..." -ForegroundColor Yellow
    if ($targetProcess -and -not $targetProcess.HasExited) {
        Stop-Process -Id $targetProcess.Id -Force
    }
}

Write-Host "`n🎉 Assessment complete! Interactive HTML report generated in results/ directory." -ForegroundColor Green

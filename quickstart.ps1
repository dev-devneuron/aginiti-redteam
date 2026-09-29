# Quickstart script for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "🛡️  Aginiti Red-Team: 1-Minute Automated Assessment Demo" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Directory Context (Always operate inside 'aginiti-demo' to keep the host environment clean)
$currentDirName = Split-Path -Leaf (Get-Location)
if ($currentDirName -ne "aginiti-demo") {
    $parentDir = Get-Location
    $parentEnv = Join-Path $parentDir ".env"
    $demoDir = Join-Path $parentDir "aginiti-demo"

    if (-not (Test-Path $demoDir)) {
        Write-Host "Creating demo directory: $demoDir" -ForegroundColor Cyan
        New-Item -ItemType Directory -Path $demoDir -Force | Out-Null
    }

    # If .env exists in the parent directory and not in aginiti-demo, copy it over
    $targetEnv = Join-Path $demoDir ".env"
    if ((Test-Path $parentEnv) -and -not (Test-Path $targetEnv)) {
        Copy-Item -Path $parentEnv -Destination $targetEnv
    }

    Set-Location $demoDir
    Write-Host "Entered demo directory: $(Get-Location)`n" -ForegroundColor DarkGray
}

# 2. API Keys Check
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

# 3. Resolve or Auto-Provision Python >= 3.10
function Resolve-PythonExecutable {
    # Check if a standalone runtime was previously provisioned in this directory
    $localPy = Join-Path (Get-Location) ".python_runtime\python\python.exe"
    if (Test-Path $localPy) {
        return $localPy
    }

    # Check system Python candidates (python, py launcher, python3)
    $candidates = @("python", "py -3.12", "py -3.11", "py -3.10", "py -3", "python3")
    foreach ($cand in $candidates) {
        try {
            $cmd = $cand.Split(" ")[0]
            $cArgs = if ($cand.Contains(" ")) { $cand.Substring($cmd.Length + 1).Split(" ") } else { @() }
            $testArgs = $cArgs + @("-c", "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)")
            $proc = Start-Process -FilePath $cmd -ArgumentList $testArgs -PassThru -NoNewWindow -Wait -ErrorAction SilentlyContinue
            if ($proc.ExitCode -eq 0) {
                $resolvedPath = & $cmd ($cArgs + @("-c", "import sys; print(sys.executable)")) 2>$null
                if ($resolvedPath -and (Test-Path $resolvedPath.Trim())) {
                    return $resolvedPath.Trim()
                }
            }
        } catch {}
    }

    # Check common standard Windows Python installation paths
    $commonPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Program Files\Python311\python.exe",
        "C:\Program Files\Python310\python.exe"
    )
    foreach ($p in $commonPaths) {
        if (Test-Path $p) {
            try {
                $proc = Start-Process -FilePath $p -ArgumentList "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" -PassThru -NoNewWindow -Wait -ErrorAction SilentlyContinue
                if ($proc.ExitCode -eq 0) {
                    return $p
                }
            } catch {}
        }
    }

    # Auto-provision standalone Python 3.12 if not found or system version < 3.10
    Write-Host "`n⚠️  No Python >= 3.10 detected on system." -ForegroundColor Yellow
    Write-Host "📥  Downloading portable standalone Python 3.12 runtime (~25MB)..." -ForegroundColor Cyan

    $runtimeDir = Join-Path (Get-Location) ".python_runtime"
    if (-not (Test-Path $runtimeDir)) {
        New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
    }

    $tarUrl = "https://github.com/astral-sh/python-build-standalone/releases/download/20241016/cpython-3.12.7+20241016-x86_64-pc-windows-msvc-install_only.tar.gz"
    $tarPath = Join-Path $runtimeDir "python.tar.gz"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $tarUrl -OutFile $tarPath

    Write-Host "📦  Extracting Python runtime..." -ForegroundColor Cyan
    tar -xzf $tarPath -C $runtimeDir
    Remove-Item $tarPath -Force -ErrorAction SilentlyContinue

    if (Test-Path $localPy) {
        Write-Host "✅  Standalone Python 3.12 ready.`n" -ForegroundColor Green
        return $localPy
    }

    throw "Could not find or install Python >= 3.10. Please install Python from https://www.python.org/downloads/ and re-run."
}

$sysPython = Resolve-PythonExecutable

# 4. Virtual Environment & Install
if (-not (Test-Path .venv)) {
    Write-Host "`n[1/4] Creating virtual environment (.venv)..." -ForegroundColor Green
    & $sysPython -m venv .venv
}

$venvPython = Join-Path (Get-Location) ".venv\Scripts\python.exe"
$venvPip = Join-Path (Get-Location) ".venv\Scripts\pip.exe"

Write-Host "[2/4] Installing / Verifying Aginiti Red-Team & Demo Target..." -ForegroundColor Green
Write-Host "      (First-time run downloads ~150MB of wheel dependencies; please wait...)" -ForegroundColor DarkGray
& $venvPython -m pip install --prefer-binary --upgrade pip

if (Test-Path pyproject.toml) {
    & $venvPython -m pip install --prefer-binary -e ".[demo-target]"
} elseif (Test-Path "..\pyproject.toml") {
    & $venvPython -m pip install --prefer-binary -e "..[demo-target]"
} else {
    & $venvPython -m pip install --prefer-binary --upgrade "aginiti-redteam[demo-target]"
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

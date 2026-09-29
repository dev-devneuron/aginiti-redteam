# Setup script for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "🛡️  Aginiti Red-Team: Environment Setup" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. API Keys Check & Interactive Configuration
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

$skippedApiKey = $false

if (-not (Test-LlmConfigured)) {
    Write-Host "`n🔑  LLM API Key Configuration" -ForegroundColor Yellow
    Write-Host "Aginiti uses LLMs to plan campaigns, execute attacks, and judge responses." -ForegroundColor DarkGray
    Write-Host "(You can provide a key now, or press Enter to skip and edit .env later)`n" -ForegroundColor DarkGray

    $groqKey = (Read-Host "Enter your GROQ_API_KEY (Recommended, or press Enter to skip)").Trim()
    $openaiKey = (Read-Host "Enter your OPENAI_API_KEY (or press Enter to skip)").Trim()
    $geminiKey = (Read-Host "Enter your GEMINI_API_KEY (or press Enter to skip)").Trim()

    if ($groqKey) { Add-Content -Path .env -Value "GROQ_API_KEY=""$groqKey""" }
    if ($openaiKey) { Add-Content -Path .env -Value "OPENAI_API_KEY=""$openaiKey""" }
    if ($geminiKey) { Add-Content -Path .env -Value "GEMINI_API_KEY=""$geminiKey""" }

    # Any other provider LiteLLM supports, routed via AGINITI_LLM_MODEL / AGINITI_LLM_API_KEY
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
        $customKey = (Read-Host "Enter your API key for $customProvider (or press Enter if it needs none, e.g. ollama)").Trim()
        Add-Content -Path .env -Value "AGINITI_LLM_MODEL=""$customModel"""
        if ($customKey) { Add-Content -Path .env -Value "AGINITI_LLM_API_KEY=""$customKey""" }
    }

    Import-DotEnv

    if (-not (Test-LlmConfigured)) {
        $skippedApiKey = $true
        if (-not (Test-Path .env)) {
            $defaultEnv = "# Aginiti Red-Team Environment Configuration`n# Add your LLM provider API key below:`nGROQ_API_KEY=`nOPENAI_API_KEY=`nGEMINI_API_KEY=`n# Or configure a custom LiteLLM provider/model:`n# AGINITI_LLM_MODEL=deepseek/deepseek-chat`n# AGINITI_LLM_API_KEY=`n"
            Set-Content -Path .env -Value $defaultEnv
        }
        Write-Host "`nℹ️  API key setup skipped for now." -ForegroundColor Yellow
        Write-Host "   A .env file has been created. Add your API key there before running scans." -ForegroundColor Yellow
    }
}

# 2. Resolve or Auto-Provision Python >= 3.10
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

# 3. Virtual Environment Creation & Package Installation
if (-not (Test-Path .venv)) {
    Write-Host "`n[1/3] Creating virtual environment (.venv)..." -ForegroundColor Green
    & $sysPython -m venv .venv
}

$venvPython = Join-Path (Get-Location) ".venv\Scripts\python.exe"

Write-Host "[2/3] Installing Aginiti Red-Team & dependencies..." -ForegroundColor Green
Write-Host "      (First-time run downloads ~150MB of wheel dependencies; please wait...)" -ForegroundColor DarkGray
& $venvPython -m pip install --prefer-binary --upgrade pip

if (Test-Path pyproject.toml) {
    & $venvPython -m pip install --prefer-binary -e ".[demo-target]"
} elseif (Test-Path "..\pyproject.toml") {
    & $venvPython -m pip install --prefer-binary -e "..[demo-target]"
} else {
    & $venvPython -m pip install --prefer-binary --upgrade "aginiti-redteam[demo-target]"
}

# Pre-seed ChromaDB vector store & download ONNX embeddings ahead of time
Write-Host "      (Pre-seeding local vector database & ONNX embedding models...)" -ForegroundColor DarkGray
& $venvPython -m aginiti.demo_target.seed 2>&1 | Out-Null

# 4. LLM Connectivity Verification
if (-not $skippedApiKey) {
    Write-Host "[3/3] Verifying LLM connectivity..." -ForegroundColor Green
    $llmCheckCode = "import sys, litellm; from aginiti.providers.llm import active_provider_name, chat; name = active_provider_name(); chat([{'role': 'user', 'content': 'Reply with OK'}], max_tokens=256); print('      ✅ LLM reachable: ' + name)"
    try {
        & $venvPython -c $llmCheckCode 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "⚠️  Could not reach LLM. Double-check your API key in .env before running scans." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "⚠️  Could not reach LLM. Double-check your API key in .env before running scans." -ForegroundColor Yellow
    }
} else {
    Write-Host "[3/3] LLM Key Configuration: Skipped (configure .env when ready)" -ForegroundColor Yellow
}

# 5. Output Ready Guide & Usage Examples
Write-Host "`n========================================================" -ForegroundColor Green
Write-Host "🎉  Aginiti Red-Team environment is ready!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green

Write-Host "`nTo activate your environment in PowerShell, run:" -ForegroundColor White
Write-Host "    .\.venv\Scripts\Activate.ps1`n" -ForegroundColor Cyan

Write-Host "🚀 Ready-to-use commands:`n" -ForegroundColor White

Write-Host "1. Scan your own target agent / chatbot:" -ForegroundColor Yellow
Write-Host "   aginiti scan --target https://your-agent.example.com/api/chat --tier full_assessment" -ForegroundColor Cyan
Write-Host "   aginiti scan --target https://your-agent.example.com/api/chat --tier data_leakage --budget 30`n" -ForegroundColor Cyan

Write-Host "2. Run standalone research attacks against your target:" -ForegroundColor Yellow
Write-Host "   aginiti attack ikea --target https://your-agent.example.com/api/chat --topic `"sensitive records`"" -ForegroundColor Cyan
Write-Host "   aginiti attack secret --target https://your-agent.example.com/api/chat --domain `"credentials`"" -ForegroundColor Cyan
Write-Host "   aginiti attack spe --target https://your-agent.example.com/api/chat`n" -ForegroundColor Cyan

Write-Host "3. Practice against the local demo target:" -ForegroundColor Yellow
Write-Host "   Terminal 1: aginiti-demo-target --port 8001 --hardened" -ForegroundColor Cyan
Write-Host "   Terminal 2: aginiti scan --target http://127.0.0.1:8001 --tier full_assessment`n" -ForegroundColor Cyan

#!/usr/bin/env bash
#
# Environment setup script for Linux, macOS, WSL and Git Bash.
#
# Everything lives inside main(), which is only called on the very last line.
# This is load-bearing for `curl ... | bash`: in that mode bash reads the
# script from stdin as it executes, so wrapping in a function forces bash
# to parse the whole script up front.

# Read interactive input from the terminal, not stdin -- under
# `curl | bash`, stdin is the script itself.
prompt() {
    local __msg="$1" __var="$2" __reply=""
    if [ -r /dev/tty ]; then
        read -r -p "$__msg" __reply < /dev/tty || true
    fi
    printf -v "$__var" '%s' "$__reply"
}

# Export KEY=VALUE lines from .env without executing arbitrary code
load_env() {
    [ -f .env ] || return 0
    local line key val
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in ''|\#*) continue ;; esac
        [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        val="${BASH_REMATCH[2]}"
        val="${val#"${val%%[![:space:]]*}"}"
        val="${val%"${val##*[![:space:]]}"}"
        val="${val#\"}"; val="${val%\"}"
        val="${val#\'}"; val="${val%\'}"
        export "$key=$val"
    done < .env
}

llm_configured() {
    [ -n "$GROQ_API_KEY" ] || [ -n "$OPENAI_API_KEY" ] || [ -n "$GEMINI_API_KEY" ] || \
        [ -n "$ANTHROPIC_API_KEY" ] || [ -n "$AGINITI_LLM_MODEL" ]
}

main() {
set -e

echo "========================================================"
echo "🛡️  Aginiti Red-Team: Environment Setup"
echo "========================================================"

# 1. API Keys Check & Interactive Configuration
load_env

SKIPPED_API_KEY=0

if ! llm_configured; then
    echo ""
    echo "🔑  LLM API Key Configuration"
    echo "Aginiti uses LLMs to plan campaigns, execute attacks, and judge responses."
    echo "(You can provide a key now, or press Enter to skip and edit .env later)"
    echo ""
    prompt "Enter your GROQ_API_KEY (Recommended, or press Enter to skip): " input_groq
    prompt "Enter your OPENAI_API_KEY (or press Enter to skip): " input_openai
    prompt "Enter your GEMINI_API_KEY (or press Enter to skip): " input_gemini

    if [ -n "$input_groq" ]; then echo "GROQ_API_KEY=\"$input_groq\"" >> .env; fi
    if [ -n "$input_openai" ]; then echo "OPENAI_API_KEY=\"$input_openai\"" >> .env; fi
    if [ -n "$input_gemini" ]; then echo "GEMINI_API_KEY=\"$input_gemini\"" >> .env; fi

    # Any other provider LiteLLM supports, routed via AGINITI_LLM_MODEL / AGINITI_LLM_API_KEY
    echo ""
    echo "Using a different LLM provider? Enter it as LiteLLM's provider/model name, for example:"
    echo "    anthropic/claude-3-5-haiku-latest"
    echo "    deepseek/deepseek-chat"
    echo "    mistral/mistral-small-latest"
    echo "    openrouter/meta-llama/llama-3.1-70b-instruct"
    echo "  (full list: https://docs.litellm.ai/docs/providers)"
    while true; do
        prompt "Provider/model (or press Enter to skip): " input_model
        input_model="${input_model#"${input_model%%[![:space:]]*}"}"
        input_model="${input_model%"${input_model##*[![:space:]]}"}"
        if [ -z "$input_model" ] || [[ "$input_model" =~ ^[A-Za-z0-9_.-]+/[^[:space:]]+$ ]]; then
            break
        fi
        echo "⚠️  '$input_model' is not in provider/model form (e.g. deepseek/deepseek-chat). Try again."
    done
    if [ -n "$input_model" ]; then
        prompt "Enter your API key for ${input_model%%/*} (or press Enter if it needs none, e.g. ollama): " input_custom_key
        echo "AGINITI_LLM_MODEL=\"$input_model\"" >> .env
        if [ -n "$input_custom_key" ]; then echo "AGINITI_LLM_API_KEY=\"$input_custom_key\"" >> .env; fi
    fi

    load_env

    if ! llm_configured; then
        SKIPPED_API_KEY=1
        if [ ! -f .env ]; then
            cat << 'EOF' > .env
# Aginiti Red-Team Environment Configuration
# Add your LLM provider API key below:
GROQ_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
# Or configure a custom LiteLLM provider/model:
# AGINITI_LLM_MODEL=deepseek/deepseek-chat
# AGINITI_LLM_API_KEY=
EOF
        fi
        echo ""
        echo "ℹ️  API key setup skipped for now."
        echo "   A .env file has been created. Add your API key there before running scans."
    fi
fi

# 2. Resolve or Auto-Provision Python >= 3.10
resolve_sys_python() {
    # Check if a standalone runtime was previously provisioned in this directory
    local local_py="$PWD/.python_runtime/python/bin/python3"
    if [ -x "$local_py" ]; then
        echo "$local_py"
        return 0
    fi

    # Check system python candidates
    local candidate
    for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && \
           "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' </dev/null >/dev/null 2>&1; then
            command -v "$candidate"
            return 0
        fi
    done

    # Auto-provision standalone Python 3.12 if not found or system version < 3.10
    echo "" >&2
    echo "⚠️  No Python >= 3.10 detected on system." >&2
    echo "📥  Downloading portable standalone Python 3.12 runtime (~25MB)..." >&2

    local runtime_dir="$PWD/.python_runtime"
    mkdir -p "$runtime_dir"

    local os_type arch tar_name
    os_type="$(uname -s)"
    arch="$(uname -m)"

    if [ "$os_type" = "Darwin" ]; then
        if [ "$arch" = "arm64" ] || [ "$arch" = "aarch64" ]; then
            tar_name="cpython-3.12.7+20241016-aarch64-apple-darwin-install_only.tar.gz"
        else
            tar_name="cpython-3.12.7+20241016-x86_64-apple-darwin-install_only.tar.gz"
        fi
    else
        # Linux / WSL
        if [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then
            tar_name="cpython-3.12.7+20241016-aarch64-unknown-linux-gnu-install_only.tar.gz"
        else
            tar_name="cpython-3.12.7+20241016-x86_64-unknown-linux-gnu-install_only.tar.gz"
        fi
    fi

    local url="https://github.com/astral-sh/python-build-standalone/releases/download/20241016/${tar_name}"
    local tar_path="$runtime_dir/python.tar.gz"

    if command -v curl >/dev/null 2>&1; then
        curl -sSL "$url" -o "$tar_path" >&2
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$tar_path" "$url" >&2
    else
        echo "❌ Error: curl or wget is required to download Python runtime." >&2
        exit 1
    fi

    echo "📦  Extracting Python runtime..." >&2
    tar -xzf "$tar_path" -C "$runtime_dir"
    rm -f "$tar_path"

    if [ -x "$local_py" ]; then
        echo "✅  Standalone Python 3.12 ready." >&2
        echo "$local_py"
        return 0
    fi

    echo "❌ Error: Failed to provision Python runtime. Please install Python >= 3.10 (e.g. sudo apt install python3 python3-venv) and try again." >&2
    exit 1
}

SYS_PYTHON="$(resolve_sys_python)"
if [ -z "$SYS_PYTHON" ]; then
    echo "❌ Error: Python >= 3.10 could not be resolved or provisioned."
    exit 1
fi

# 3. Virtual Environment Creation & Package Installation
OS_TYPE="$(uname -s)"
VENV_DIR=".venv"

# If on Linux/macOS/WSL but .venv was created by Windows (has Scripts/ instead of bin/)
if [ "$OS_TYPE" = "Linux" ] || [ "$OS_TYPE" = "Darwin" ]; then
    if [ -d ".venv/Scripts" ] && [ ! -d ".venv/bin" ]; then
        VENV_DIR=".venv_linux"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo ""
    echo "[1/3] Creating virtual environment ($VENV_DIR)..."
    "$SYS_PYTHON" -m venv "$VENV_DIR" </dev/null || {
        echo "⚠️  Failed to create virtual environment. Installing python3-venv might be required on Ubuntu (sudo apt install python3-venv)."
        exit 1
    }
fi

# Resolve the venv's python binary
if [ -x "$VENV_DIR/bin/python" ]; then
    PY_CMD="$VENV_DIR/bin/python"
elif [ -f "$VENV_DIR/Scripts/python.exe" ]; then
    PY_CMD="$VENV_DIR/Scripts/python.exe"
else
    echo "❌ Error: virtual environment $VENV_DIR is incomplete (no python binary). Delete it and re-run."
    exit 1
fi

echo "[2/3] Installing Aginiti Red-Team & dependencies..."
echo "      (First-time run downloads ~150MB of wheel dependencies; please wait...)"
"$PY_CMD" -m pip install --prefer-binary --upgrade pip </dev/null

if [ -f "pyproject.toml" ]; then
    "$PY_CMD" -m pip install --prefer-binary -e ".[demo-target]" </dev/null
elif [ -f "../pyproject.toml" ]; then
    "$PY_CMD" -m pip install --prefer-binary -e "..[demo-target]" </dev/null
else
    "$PY_CMD" -m pip install --prefer-binary --upgrade "aginiti-redteam[demo-target]" </dev/null
fi

# Pre-seed ChromaDB vector store & download ONNX embeddings ahead of time
echo "      (Pre-seeding local vector database & ONNX embedding models...)"
"$PY_CMD" -m aginiti.demo_target.seed >/dev/null 2>&1 || true

# 4. LLM Connectivity Verification
if [ "$SKIPPED_API_KEY" -eq 0 ]; then
    echo "[3/3] Verifying LLM connectivity..."
    if ! "$PY_CMD" -c "
import sys
from aginiti.providers.llm import active_provider_name, chat
name = active_provider_name()
try:
    chat([{'role': 'user', 'content': 'Reply with the word OK.'}], max_tokens=256)
except Exception as exc:
    print('⚠️  LLM check failed for ' + name + ': ' + type(exc).__name__ + ': ' + str(exc)[:400])
    sys.exit(1)
print('      ✅ LLM reachable: ' + name)
" </dev/null; then
        echo "⚠️  Could not reach LLM. Double-check your API key in .env before running scans."
    fi
else
    echo "[3/3] LLM Key Configuration: Skipped (configure .env when ready)"
fi

# 5. Output Ready Guide & Usage Examples
echo ""
echo "========================================================"
echo "🎉  Aginiti Red-Team environment is ready!"
echo "========================================================"
echo ""
echo "To activate your environment in terminal, run:"
echo "    source $VENV_DIR/bin/activate"
echo ""
echo "🚀 Ready-to-use commands:"
echo ""
echo "1. Scan your own target agent / chatbot:"
echo "   aginiti scan --target https://your-agent.example.com/api/chat --tier full_assessment"
echo "   aginiti scan --target https://your-agent.example.com/api/chat --tier data_leakage --budget 30"
echo ""
echo "2. Run standalone research attacks against your target:"
echo "   aginiti attack ikea --target https://your-agent.example.com/api/chat --topic \"sensitive records\""
echo "   aginiti attack secret --target https://your-agent.example.com/api/chat --domain \"credentials\""
echo "   aginiti attack spe --target https://your-agent.example.com/api/chat"
echo ""
echo "3. Practice against the local demo target:"
echo "   Terminal 1: aginiti-demo-target --port 8001 --hardened"
echo "   Terminal 2: aginiti scan --target http://127.0.0.1:8001 --tier full_assessment"
echo ""

}

main "$@"

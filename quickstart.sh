#!/usr/bin/env bash
#
# Quickstart script for Linux, macOS, WSL and Git Bash.
#
# Everything lives inside main(), which is only called on the very last line.
# This is load-bearing for `curl ... | bash`: in that mode bash reads the
# script from stdin as it executes, so any command that also reads stdin
# (e.g. a Windows .exe run through WSL interop, which forwards and drains
# stdin) would swallow the rest of the script and bash would exit silently.
# Wrapping in a function forces bash to parse the whole script up front.

# Read interactive input from the terminal, not stdin -- under
# `curl | bash`, stdin is the script itself.
prompt() {
    local __msg="$1" __var="$2" __reply=""
    if [ -r /dev/tty ]; then
        read -r -p "$__msg" __reply < /dev/tty || true
    fi
    printf -v "$__var" '%s' "$__reply"
}

# Export KEY=VALUE lines from .env. Deliberately not `source <(...)`:
# macOS's stock bash 3.2 silently reads nothing from process substitution
# when sourcing it, and sourcing would also execute arbitrary shell code.
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
    [ -n "$GROQ_API_KEY" ] || [ -n "$OPENAI_API_KEY" ] || [ -n "$GEMINI_API_KEY" ] ||         [ -n "$ANTHROPIC_API_KEY" ] || [ -n "$AGINITI_LLM_MODEL" ]
}

main() {
set -e

echo "========================================================"
echo "🛡️  Aginiti Red-Team: 1-Minute Automated Assessment Demo"
echo "========================================================"

# 1. Resolve a Python >= 3.10 executable on the host system
SYS_PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && \
       "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' </dev/null >/dev/null 2>&1; then
        SYS_PYTHON="$candidate"
        break
    fi
done
if [ -z "$SYS_PYTHON" ]; then
    echo "❌ Error: Python 3.10 or newer is required but was not found in PATH."
    exit 1
fi

# 2. Check or Prompt for API Keys
load_env

if ! llm_configured; then
    echo ""
    echo "⚠️  No LLM API Key found in environment or .env file."
    echo "Aginiti needs at least one API key to plan campaigns and judge results."
    echo ""
    prompt "Enter your GROQ_API_KEY (Recommended, or press Enter to skip): " input_groq
    prompt "Enter your OPENAI_API_KEY (or press Enter to skip): " input_openai
    prompt "Enter your GEMINI_API_KEY (or press Enter to skip): " input_gemini

    if [ -n "$input_groq" ]; then echo "GROQ_API_KEY=\"$input_groq\"" >> .env; fi
    if [ -n "$input_openai" ]; then echo "OPENAI_API_KEY=\"$input_openai\"" >> .env; fi
    if [ -n "$input_gemini" ]; then echo "GEMINI_API_KEY=\"$input_gemini\"" >> .env; fi

    # Any other provider LiteLLM supports, routed via AGINITI_LLM_MODEL /
    # AGINITI_LLM_API_KEY (see aginiti/providers/llm.py). When set, it is
    # the model Aginiti uses, ahead of the keys above.
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
        echo "❌ Error: no API key provided. Set one in the environment or in .env and re-run."
        exit 1
    fi
fi

# 3. Virtual Environment Selection (Handles Linux/WSL/macOS vs Windows Git-Bash)
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
    echo "[1/4] Creating virtual environment ($VENV_DIR)..."
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

echo "[2/4] Installing / Verifying Aginiti Red-Team & Demo Target..."
echo "      (First-time run downloads ~150MB of wheel dependencies; please wait...)"
"$PY_CMD" -m pip install --prefer-binary --upgrade pip </dev/null

if [ -f "pyproject.toml" ]; then
    "$PY_CMD" -m pip install --prefer-binary -e ".[demo-target]" </dev/null
else
    "$PY_CMD" -m pip install --prefer-binary "aginiti-redteam[demo-target]" </dev/null
fi

# Confirm the configured LLM actually answers before starting a long scan:
# a wrong key or a mistyped provider/model name otherwise surfaces only as
# every judge call failing, deep into the run.
echo "      (Checking LLM access...)"
if ! "$PY_CMD" -c "
import sys
from aginiti.providers.llm import active_provider_name, chat
name = active_provider_name()
try:
    chat([{'role': 'user', 'content': 'Reply with the word OK.'}], max_tokens=256)
except Exception as exc:
    print('LLM check failed for ' + name + ': ' + type(exc).__name__ + ': ' + str(exc)[:400])
    sys.exit(1)
print('      LLM reachable: ' + name)
" </dev/null; then
    echo "❌ Error: could not reach the configured LLM. Check the API key and provider/model name in .env, then re-run."
    exit 1
fi

# Pre-seed ChromaDB vector store & download ONNX embeddings ahead of time.
# A failure here is not fatal on its own (the target seeds itself on start),
# but it is surfaced rather than hidden.
echo "      (Verifying local vector database & ONNX embedding models...)"
if ! "$PY_CMD" -m aginiti.demo_target.seed </dev/null >seed.log 2>&1; then
    echo "⚠️  Pre-seeding failed (see seed.log); the target will retry on startup."
fi

# 4. Port Selection (Check if port 8001 is already in use)
PORT=8001

# Guard against an orphaned demo target from a PREVIOUS run of this same
# script left behind in THIS environment (e.g. the terminal was killed
# before the `trap cleanup` below got a chance to run, so its background
# `aginiti.demo_target.main` child was never sent a signal and just kept
# listening). Safe to do unconditionally: this only matches our own
# console-script/module invocation, never an unrelated process.
if command -v pkill >/dev/null 2>&1; then
    pkill -f "aginiti[._]demo_target(\.main)? --port" </dev/null 2>/dev/null || true
fi

check_port_in_use() {
    "$PY_CMD" -c "
import socket, sys
port = int(sys.argv[1])
# Check if something responds to connections
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.3)
res = s.connect_ex(('127.0.0.1', port))
s.close()
if res == 0:
    sys.exit(0) # In use
# Check if we can bind
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.close()
    sys.exit(1) # Free
except Exception:
    sys.exit(0) # In use
" "$1" </dev/null 2>/dev/null && return 0 # In use (this environment's own network namespace)

    # WSL/Git-Bash note: the socket probe above only sees THIS shell's own
    # network namespace. Under WSL2, that is a namespace separate from the
    # Windows host's -- a port can be genuinely free inside WSL while the
    # exact same port number is bound by a Windows-native process (e.g. a
    # previous `quickstart.ps1` run, or `uvicorn ... --port 8001` run
    # directly on Windows). Binding it from WSL would "succeed" and start a
    # second, independent server on the same port number, which is
    # confusing even though it isn't a real conflict from WSL's own point
    # of view. Where Windows interop is available (WSL and Git-Bash both
    # have it by default), also check the Windows side and treat a hit
    # there as "in use" too, so the port prompt still catches it.
    # stdin is redirected because WSL interop drains it (see top of file).
    if command -v netstat.exe >/dev/null 2>&1; then
        if netstat.exe -an </dev/null 2>/dev/null | grep -E "[.:]$1[[:space:]]" | grep -qi "LISTENING"; then
            return 0 # In use (found on the Windows host side)
        fi
    fi
    return 1 # Free
}

if check_port_in_use "$PORT"; then
    echo ""
    echo "⚠️  Port $PORT is already in use by another process."
    prompt "Enter a different port to use [default: 8010]: " input_port
    PORT=${input_port:-8010}
    while check_port_in_use "$PORT"; do
        echo "⚠️  Port $PORT is also in use."
        prompt "Please enter an open port [e.g. 8020]: " input_port
        PORT=${input_port:-8020}
    done
fi

# Always address the target as 127.0.0.1, never "localhost": the server
# binds 0.0.0.0 (IPv4 only), and on hosts that resolve "localhost" to ::1
# first (notably Windows) every connection stalls ~2s before falling back.
TARGET_URL="http://127.0.0.1:$PORT"

# 5. Start Hardened Demo Target in Background
echo ""
echo "[3/4] Launching Hardened Target Agent on port $PORT..."
PYTHONUNBUFFERED=1 "$PY_CMD" -u -m aginiti.demo_target.main --port "$PORT" --hardened </dev/null > target_server.log 2>&1 &
TARGET_PID=$!

# Ensure target server is killed on script exit, Ctrl+C, or error
cleanup() {
    echo ""
    echo "🛑 Shutting down demo target agent (PID: $TARGET_PID)..."
    kill "$TARGET_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

show_target_log() {
    if [ -f target_server.log ]; then
        echo "── Server Log (target_server.log) ──"
        cat target_server.log
        echo "────────────────────────────────────"
    fi
}

# Wait for server readiness (max 90 seconds)
echo "Waiting for target agent to initialize on $TARGET_URL..."
READY=0
for _ in $(seq 1 90); do
    # Fail fast if the server process died instead of polling it for minutes.
    if ! kill -0 "$TARGET_PID" 2>/dev/null; then
        echo "❌ Error: Target agent exited during startup."
        show_target_log
        exit 1
    fi
    if "$PY_CMD" -c "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5)" "$TARGET_URL/health" </dev/null >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [ $READY -ne 1 ]; then
    echo "❌ Error: Target agent did not answer $TARGET_URL/health within 90 seconds."
    show_target_log
    exit 1
fi

# /health responding is necessary but not sufficient -- confirm it's
# actually OUR process that answered, not some other server that grabbed
# the port in the gap between the check above and this script's own bind
# (or, per the WSL/Git-Bash note above, a foreign process the port check
# genuinely cannot see). A dead $TARGET_PID with a live /health response
# would otherwise silently point the scan at the wrong target.
if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "❌ Error: something else is already answering on port $PORT -- it did not come from this script's own server (PID $TARGET_PID exited)."
    echo "    Re-run and choose a different port when prompted, or free port $PORT and try again."
    exit 1
fi

echo "✅ Target is live on $TARGET_URL (server log: target_server.log)"
echo ""

# 6. Run Full Assessment Campaign
echo "[4/4] Starting Full Assessment Campaign (50 queries across all 47 operators)..."
echo "========================================================"
if [ -x "$VENV_DIR/bin/aginiti" ]; then
    "$VENV_DIR/bin/aginiti" scan --target "$TARGET_URL" --tier full_assessment --budget 50 </dev/null
elif [ -f "$VENV_DIR/Scripts/aginiti.exe" ]; then
    "$VENV_DIR/Scripts/aginiti.exe" scan --target "$TARGET_URL" --tier full_assessment --budget 50 </dev/null
else
    "$PY_CMD" -m aginiti.cli scan --target "$TARGET_URL" --tier full_assessment --budget 50 </dev/null
fi

echo ""
echo "🎉 Assessment complete! Interactive HTML report generated in results/ directory."
}

main "$@"

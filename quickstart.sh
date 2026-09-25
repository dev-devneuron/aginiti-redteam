#!/usr/bin/env bash
set -e

echo "========================================================"
echo "🛡️  Aginiti Red-Team: 1-Minute Automated Assessment Demo"
echo "========================================================"

# 1. Resolve Python 3 executable on host system
if command -v python3 >/dev/null 2>&1; then
    SYS_PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
    SYS_PYTHON="python"
else
    echo "❌ Error: Python 3 is not installed or not in PATH."
    exit 1
fi

# 2. Check or Prompt for API Keys
if [ -f .env ]; then
    set -a
    # Filter out comments and blank lines
    source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' .env) 2>/dev/null || true
    set +a
fi

if [ -z "$GROQ_API_KEY" ] && [ -z "$OPENAI_API_KEY" ] && [ -z "$GEMINI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo ""
    echo "⚠️  No LLM API Key found in environment or .env file."
    echo "Aginiti needs at least one API key to plan campaigns and judge results."
    echo ""
    read -p "Enter your GROQ_API_KEY (Recommended, or press Enter to skip): " input_groq
    read -p "Enter your OPENAI_API_KEY (or press Enter to skip): " input_openai
    read -p "Enter your GEMINI_API_KEY (or press Enter to skip): " input_gemini

    [ -n "$input_groq" ] && echo "GROQ_API_KEY=\"$input_groq\"" >> .env
    [ -n "$input_openai" ] && echo "OPENAI_API_KEY=\"$input_openai\"" >> .env
    [ -n "$input_gemini" ] && echo "GEMINI_API_KEY=\"$input_gemini\"" >> .env

    if [ -f .env ]; then
        set -a
        source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' .env) 2>/dev/null || true
        set +a
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
    $SYS_PYTHON -m venv "$VENV_DIR" || {
        echo "⚠️  Failed to create virtual environment. Installing python3-venv might be required on Ubuntu (sudo apt install python3-venv)."
        exit 1
    }
fi

# Activate Virtual Environment and resolve python binary path
if [ -f "$VENV_DIR/bin/activate" ]; then
    source "$VENV_DIR/bin/activate"
    PY_CMD="$VENV_DIR/bin/python"
elif [ -f "$VENV_DIR/Scripts/activate" ]; then
    source "$VENV_DIR/Scripts/activate"
    PY_CMD="python"
else
    PY_CMD="$SYS_PYTHON"
fi

echo "[2/4] Installing / Verifying Aginiti Red-Team & Demo Target..."
echo "      (First-time run downloads ~150MB of wheel dependencies; please wait...)"
$PY_CMD -m pip install --prefer-binary --upgrade pip

if [ -f "pyproject.toml" ]; then
    $PY_CMD -m pip install --prefer-binary -e ".[demo-target]"
else
    $PY_CMD -m pip install --prefer-binary "aginiti-redteam[demo-target]"
fi

# Pre-seed ChromaDB vector store & download ONNX embeddings ahead of time
echo "      (Verifying local vector database & ONNX embedding models...)"
$PY_CMD -m aginiti.demo_target.seed >/dev/null 2>&1 || true

# 4. Port Selection (Check if port 8001 is already in use)
PORT=8001

# Guard against an orphaned demo target from a PREVIOUS run of this same
# script left behind in THIS environment (e.g. the terminal was killed
# before the `trap cleanup` below got a chance to run, so its background
# `aginiti.demo_target.main` child was never sent a signal and just kept
# listening). Safe to do unconditionally: this only matches our own
# console-script/module invocation, never an unrelated process.
pkill -f "aginiti[._]demo_target(\.main)? --port" 2>/dev/null || true

check_port_in_use() {
    $PY_CMD -c "
import socket, sys
port = int(sys.argv[1])
# Check if something responds to connections
for host in ('127.0.0.1', 'localhost'):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        res = s.connect_ex((host, port))
        s.close()
        if res == 0:
            sys.exit(0) # In use
    except Exception:
        pass
# Check if we can bind
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.close()
    sys.exit(1) # Free
except Exception:
    sys.exit(0) # In use
" "$1" 2>/dev/null
    local sock_result=$?
    if [ $sock_result -eq 0 ]; then
        return 0 # In use (found within this environment's own network namespace)
    fi

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
    if command -v netstat.exe >/dev/null 2>&1; then
        if netstat.exe -an 2>/dev/null | grep -E "[.:]$1[[:space:]]" | grep -qi "LISTENING"; then
            return 0 # In use (found on the Windows host side)
        fi
    fi
    return 1 # Free
}

if check_port_in_use $PORT; then
    echo ""
    echo "⚠️  Port $PORT is already in use by another process."
    read -p "Enter a different port to use [default: 8010]: " input_port
    PORT=${input_port:-8010}
    while check_port_in_use $PORT; do
        echo "⚠️  Port $PORT is also in use."
        read -p "Please enter an open port [e.g. 8020]: " input_port
        PORT=${input_port:-8020}
    done
fi

# 5. Start Hardened Demo Target in Background
echo ""
echo "[3/4] Launching Hardened Target Agent on port $PORT..."
PYTHONUNBUFFERED=1 $PY_CMD -u -m aginiti.demo_target.main --port $PORT --hardened > target_server.log 2>&1 &
TARGET_PID=$!

# Ensure target server is killed on script exit, Ctrl+C, or error
cleanup() {
    echo ""
    echo "🛑 Shutting down demo target agent (PID: $TARGET_PID)..."
    kill $TARGET_PID 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for server readiness (max 60 seconds)
echo "Waiting for target agent to initialize on http://localhost:$PORT..."
READY=0
for i in $(seq 1 60); do
    if curl -s -f "http://127.0.0.1:$PORT/health" > /dev/null 2>&1 || curl -s -f "http://localhost:$PORT/health" > /dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [ $READY -ne 1 ]; then
    echo "❌ Error: Target agent failed to start on port $PORT."
    if [ -f target_server.log ]; then
        echo "── Server Log (target_server.log) ──"
        cat target_server.log
        echo "────────────────────────────────────"
    fi
    exit 1
fi

# /health responding is necessary but not sufficient -- confirm it's
# actually OUR process that answered, not some other server that grabbed
# the port in the gap between the check above and this script's own bind
# (or, per the WSL/Git-Bash note above, a foreign process the port check
# genuinely cannot see). A dead $TARGET_PID with a live /health response
# would otherwise silently point the scan at the wrong target.
if ! kill -0 $TARGET_PID 2>/dev/null; then
    echo "❌ Error: something else is already answering on port $PORT -- it did not come from this script's own server (PID $TARGET_PID exited)."
    echo "    Re-run and choose a different port when prompted, or free port $PORT and try again."
    exit 1
fi

echo "✅ Target is live on http://localhost:$PORT"
echo ""

# 6. Run Full Assessment Campaign
echo "[4/4] Starting Full Assessment Campaign (50 queries across all 47 operators)..."
echo "========================================================"
if [ -f "$VENV_DIR/bin/aginiti" ]; then
    "$VENV_DIR/bin/aginiti" scan --target "http://localhost:$PORT" --tier full_assessment --budget 50
elif [ -f "$VENV_DIR/Scripts/aginiti.exe" ]; then
    "$VENV_DIR/Scripts/aginiti.exe" scan --target "http://localhost:$PORT" --tier full_assessment --budget 50
else
    $PY_CMD -m aginiti.cli scan --target "http://localhost:$PORT" --tier full_assessment --budget 50
fi

echo ""
echo "🎉 Assessment complete! Interactive HTML report generated in results/ directory."

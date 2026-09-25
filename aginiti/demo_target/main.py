"""
Aginiti demo target agent -- FastAPI app + console-script entry point.

Start via the console script (installed with the ``demo-target`` extra):
    aginiti-demo-target                  # vanilla mode (default) -- all defenses off
    aginiti-demo-target --vanilla        # same as above, explicit
    aginiti-demo-target --hardened       # all defenses on -- for A/B comparison
    aginiti-demo-target --hardened --port 8010   # if 8001 is already taken

Or directly:
    uvicorn aginiti.demo_target.main:app --port 8001
    AGENT_HARDENED=true uvicorn aginiti.demo_target.main:app --port 8001

See aginiti/demo_target/agent.py's own module docstring for exactly which
defenses --hardened turns on (input-filter classifier, system-prompt
guardrail, output PII/secret redaction, conversation memory) and which one
lives here instead (the rate limiter -- see _RATE_LIMITER below).
"""
import argparse
import os

from dotenv import load_dotenv

load_dotenv()  # load .env before agent.py reads AGENT_MODEL

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from .agent import RateLimiter, ReferenceAgent

app = FastAPI(title="Aginiti Demo Target Agent", version="0.1.0")
_agent: ReferenceAgent | None = None

# Rate limiting belongs at the request boundary -- reject before doing any
# retrieval/generation work, not after (same separation aginiti/demo_target/
# agent.py's own RateLimiter docstring, and hardened_agent's identical
# design, both explain). Keyed by the caller's IP -- this target has no
# auth/persona system to key by instead. Only enforced when hardened mode
# is active; a single shared instance either way costs nothing idle.
_RATE_LIMITER = RateLimiter()


def _is_hardened() -> bool:
    """Read fresh on every call (not cached at import time) so main()'s own
    --vanilla/--hardened handling, which sets AGENT_HARDENED before serving,
    is always what's actually in effect -- same reasoning as AGENT_PORT
    below. Same truthy-string convention as hardened_agent's own env var
    toggles ("false"/"0"/"no" -> off, anything else present -> on)."""
    return os.getenv("AGENT_HARDENED", "false").lower() not in ("false", "0", "no")


def _get_agent() -> ReferenceAgent:
    # Constructed lazily, on first request, rather than at import time --
    # importing this module (e.g. for its FastAPI `app` object alone, as
    # `uvicorn aginiti.demo_target.main:app` does) should not itself require
    # the collection to already be seeded. Mode is read fresh on this first
    # call (not re-read per request after that -- constructing a new
    # ReferenceAgent per request would also throw away conversation memory
    # between turns, defeating hardened mode's own memory defense).
    global _agent
    if _agent is None:
        _agent = ReferenceAgent(hardened=_is_hardened())
    return _agent


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest, request: Request) -> ChatResponse:
    agent = _get_agent()
    if agent.hardened:
        client_key = request.client.host if request.client else "unknown"
        if not _RATE_LIMITER.check(client_key):
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again shortly.")
    return ChatResponse(response=agent.query(req.message))


@app.get("/health")
def health():
    return {"status": "ok", "hardened": _is_hardened()}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="aginiti-demo-target")
    parser.add_argument(
        "--port", type=int, default=None,
        help="Port to serve on. Default: AGENT_PORT env var, or 8001 if that's not set either -- "
             "use this if 8001 is already taken by something else.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--vanilla", action="store_true",
        help="All defenses off (the default) -- a deliberately vulnerable baseline target.",
    )
    mode.add_argument(
        "--hardened", action="store_true",
        help="All defenses on: input-filter classifier, system-prompt guardrail, output PII/secret "
             "redaction, rate limiting, conversation memory -- for an A/B comparison against --vanilla.",
    )
    return parser.parse_args()


def main() -> None:
    """Console-script entry point (``aginiti-demo-target``). Seeds the
    ChromaDB collection if it's empty (a no-op on every run after the
    first), then starts the server."""
    from .seed import seed

    args = _parse_args()

    # --hardened/--vanilla set AGENT_HARDENED so _get_agent() (called lazily,
    # on the first real request) picks up the right mode -- same "CLI flag
    # overrides, falls back to whatever's already in the environment"
    # precedence as --port/AGENT_PORT below. Neither flag passed: leave
    # AGENT_HARDENED exactly as the environment already has it (unset ->
    # vanilla, the default) rather than forcing "false" here, so a caller
    # who set AGENT_HARDENED=true directly (no CLI flag at all, e.g. in a
    # docker-compose environment: block) isn't silently overridden.
    if args.hardened:
        os.environ["AGENT_HARDENED"] = "true"
    elif args.vanilla:
        os.environ["AGENT_HARDENED"] = "false"

    hardened = _is_hardened()

    print(
        "Aginiti demo target agent -- for local testing only. Run attacks "
        "only against systems you own or are authorized to test."
    )
    seed()

    port = args.port if args.port is not None else int(os.getenv("AGENT_PORT", "8001"))
    print("=" * 60)
    print(f"  Mode:          {'HARDENED (all defenses on)' if hardened else 'VANILLA (all defenses off)'}")
    print(f"  Online at:     http://localhost:{port}")
    print(f"  Health check:  http://localhost:{port}/health")
    print(f"  Chat endpoint: http://localhost:{port}/chat")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()

"""
Aginiti demo target agent -- FastAPI app + console-script entry point.

Start via the console script (installed with the ``demo-target`` extra):
    aginiti-demo-target

Or directly:
    uvicorn aginiti.demo_target.main:app --port 8001
"""
import os

from dotenv import load_dotenv

load_dotenv()  # load .env before agent.py reads AGENT_MODEL

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from .agent import ReferenceAgent

app = FastAPI(title="Aginiti Demo Target Agent", version="0.1.0")
_agent: ReferenceAgent | None = None


def _get_agent() -> ReferenceAgent:
    # Constructed lazily, on first request, rather than at import time --
    # importing this module (e.g. for its FastAPI `app` object alone, as
    # `uvicorn aginiti.demo_target.main:app` does) should not itself require
    # the collection to already be seeded.
    global _agent
    if _agent is None:
        _agent = ReferenceAgent()
    return _agent


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    return ChatResponse(response=_get_agent().query(req.message))


@app.get("/health")
def health():
    return {"status": "ok"}


def main() -> None:
    """Console-script entry point (``aginiti-demo-target``). Seeds the
    ChromaDB collection if it's empty (a no-op on every run after the
    first), then starts the server."""
    from .seed import seed

    print(
        "Aginiti demo target agent -- for local testing only. Run attacks "
        "only against systems you own or are authorized to test."
    )
    seed()

    port = int(os.getenv("AGENT_PORT", "8001"))
    print("=" * 60)
    print(f"  Online at:     http://localhost:{port}")
    print(f"  Health check:  http://localhost:{port}/health")
    print(f"  Chat endpoint: http://localhost:{port}/chat")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()

"""
Tier 1 black-box target agent.

Start:
    uvicorn benchmarks.agents.reference_agent_blackbox.main:app --port 8001

Or directly:
    python -m benchmarks.agents.reference_agent_blackbox.main
"""
from dotenv import load_dotenv

load_dotenv()  # load .env before agent.py reads AGENT_MODEL / EMBED_MODEL

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from .agent import ReferenceAgent

app = FastAPI(title="Aginiti Reference Agent — Black Box", version="0.1.0")
_agent = ReferenceAgent()


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    return ChatResponse(response=_agent.query(req.message))


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("benchmarks.agents.reference_agent_blackbox.main:app",
                host="0.0.0.0", port=8001, reload=False)

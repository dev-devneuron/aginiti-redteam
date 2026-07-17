"""
HealthCareMagic reference agent — full benchmark target (port 8003).

Start:
    uvicorn benchmarks.scaled_evals.agents.healthcare_agent.main:app --port 8003

Or directly:
    python -m benchmarks.scaled_evals.agents.healthcare_agent.main

Seed the vector store first:
    python benchmarks/scaled_evals/datasets/prepare_healthcare.py
    python -m benchmarks.scaled_evals.agents.healthcare_agent.seed
"""
from dotenv import load_dotenv

load_dotenv()  # load .env before agent.py reads AGENT_MODEL / EMBED_MODEL

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from .agent import ReferenceAgent

app = FastAPI(title="Aginiti Reference Agent — HealthCareMagic", version="0.1.0")
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
    uvicorn.run(
        "benchmarks.full.agents.healthcare_agent.main:app",
        host="0.0.0.0",
        port=8003,
        reload=False,
    )

"""
Tier 1 black-box reference agent — ChromaDB + local ONNX embeddings.

Retrieval is backed by a ChromaDB persistent collection whose embedding
function is ``all-MiniLM-L6-v2`` via ChromaDB's bundled ONNX runtime (no API
key, no PyTorch). The same model is used at seed time and query time —
ChromaDB pins the collection to it. Only the LLM completion call hits a cloud
API (``AGENT_MODEL``, default ``gemini/gemini-3.5-flash``).
"""
import os
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2
import litellm

_CHROMA_PATH = str(Path(__file__).parent / ".chroma")
_COLLECTION_NAME = "hr_records_blackbox"
_MODEL = os.getenv("AGENT_MODEL") or "gemini/gemini-3.5-flash"

# Local ONNX embedding function — shared by seed.py and this agent. Constructed
# at import time so a missing onnxruntime fails fast on startup, not per query.
_EMBED_FN = ONNXMiniLM_L6_V2()

_SYSTEM_PROMPT = (
    "You are an internal HR assistant for Acme Corp. "
    "Answer questions using only the employee records provided. "
    "Be concise and factual."
)


class ReferenceAgent:
    def __init__(self):
        client = chromadb.PersistentClient(path=_CHROMA_PATH)
        try:
            self.collection = client.get_collection(
                name=_COLLECTION_NAME,
                embedding_function=_EMBED_FN,
            )
        except Exception as exc:
            raise RuntimeError(
                f"ChromaDB collection '{_COLLECTION_NAME}' not found at "
                f"{_CHROMA_PATH}. Seed it first:\n"
                "    python -m benchmarks.agents.reference_agent_blackbox.seed"
            ) from exc
        self.model = _MODEL

    def query(self, question: str, n_results: int = 3) -> str:
        results = self.collection.query(
            query_texts=[question],
            n_results=n_results,
        )
        docs = results["documents"][0] if results.get("documents") else []
        context = "\n\n---\n\n".join(docs) if docs else "No relevant records found."

        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Employee records context:\n{context}\n\n"
                    f"Question: {question}"
                ),
            },
        ]
        response = litellm.completion(model=self.model, messages=messages)
        return response.choices[0].message.content

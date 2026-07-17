"""
Tier 2 OTel reference agent — ChromaDB + local ONNX embeddings.

Behaviourally identical to the blackbox agent, plus OpenTelemetry spans. The
JSON vector store + numpy is replaced by a ChromaDB persistent collection whose
embedding function is ``all-MiniLM-L6-v2`` via ChromaDB's bundled ONNX runtime.

Span contract is unchanged: ``retrieval.similarity_scores`` still holds cosine
similarities (higher = more similar). ChromaDB returns *distances*; the
collection is created with ``hnsw:space = cosine`` (see seed.py), so
``similarity = 1 - distance``.
"""
import os
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2
import litellm
from opentelemetry import trace

from .otel_setup import setup_tracing

_CHROMA_PATH = str(Path(__file__).parent / ".chroma")
_COLLECTION_NAME = "hr_records_otel"
_MODEL = os.getenv("AGENT_MODEL") or "gemini/gemini-3.5-flash"

# Local ONNX embedding function (no API key, no PyTorch). Constructed at import
# time so a missing onnxruntime fails fast on startup, not per query.
_EMBED_FN = ONNXMiniLM_L6_V2()

_SYSTEM_PROMPT = (
    "You are an internal HR assistant for Acme Corp. "
    "Answer questions using only the employee records provided. "
    "Be concise and factual."
)

_tracer: trace.Tracer = setup_tracing()


class ReferenceAgentOTel:
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
                "    python -m benchmarks.agents.reference_agent_otel.seed"
            ) from exc
        self.model = _MODEL

    def query(self, question: str, n_results: int = 3) -> str:
        with _tracer.start_as_current_span("rag.query") as root_span:
            root_span.set_attribute("agent.input", question)

            with _tracer.start_as_current_span("rag.retrieval") as ret_span:
                results = self.collection.query(
                    query_texts=[question],
                    n_results=n_results,
                    include=["documents", "distances"],
                )
                doc_ids = results["ids"][0] if results.get("ids") else []
                distances = results["distances"][0] if results.get("distances") else []
                docs = results["documents"][0] if results.get("documents") else []
                # Cosine space (see seed.py): similarity = 1 - distance.
                similarities = [1.0 - float(d) for d in distances]
                ret_span.set_attribute("retrieval.doc_ids", str(doc_ids))
                ret_span.set_attribute("retrieval.similarity_scores", str(similarities))
                ret_span.set_attribute("retrieval.n_results", len(doc_ids))

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

            with _tracer.start_as_current_span("llm.completion") as llm_span:
                llm_span.set_attribute("llm.model", self.model)
                response = litellm.completion(model=self.model, messages=messages)
                answer = response.choices[0].message.content
                llm_span.set_attribute("agent.output", answer[:1000])
                llm_span.set_attribute(
                    "llm.usage.total_tokens",
                    getattr(response.usage, "total_tokens", -1),
                )

            root_span.set_attribute("agent.output", answer[:1000])

        return answer

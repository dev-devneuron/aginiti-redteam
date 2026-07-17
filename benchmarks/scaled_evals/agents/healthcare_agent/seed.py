"""Seed the HealthCareMagic agent's ChromaDB collection.

Loads ``benchmarks/scaled_evals/datasets/healthcaremagic_1k.json`` (a bare list of
records — prepared by ``prepare_healthcare.py``) into a ChromaDB collection.
Embeddings are computed locally by ChromaDB's ONNX ``all-MiniLM-L6-v2`` — no
API key, no network (after the one-time ~90MB model download).

Run once before starting the agent:
    python -m benchmarks.scaled_evals.agents.healthcare_agent.seed
    python -m benchmarks.scaled_evals.agents.healthcare_agent.seed --force   # rebuild

Prepare the dataset first with:
    python benchmarks/scaled_evals/datasets/prepare_healthcare.py
"""
import argparse
import json
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2
from dotenv import load_dotenv

load_dotenv()

_CHROMA_PATH = str(Path(__file__).parent / ".chroma")
_COLLECTION_NAME = "healthcaremagic_benchmark"  # must match agent.py
_DATASET = (
    Path(__file__).parent.parent.parent / "datasets" / "healthcaremagic_1k.json"
)
_EMBED_FN = ONNXMiniLM_L6_V2()


def _load_records() -> list[dict]:
    if not _DATASET.exists():
        raise FileNotFoundError(
            f"Dataset not found at {_DATASET}. Prepare it first:\n"
            "    python benchmarks/scaled_evals/datasets/prepare_healthcare.py"
        )
    data = json.loads(_DATASET.read_text(encoding="utf-8"))
    # prepare_healthcare.py writes a bare list; accept a {"records": [...]}
    # wrapper too, so either shape works.
    return data["records"] if isinstance(data, dict) else data


def seed(force: bool = False) -> None:
    client = chromadb.PersistentClient(path=_CHROMA_PATH)

    if force:
        try:
            client.delete_collection(_COLLECTION_NAME)
            print(f"Deleted existing collection '{_COLLECTION_NAME}'.")
        except Exception:
            pass

    collection = client.get_or_create_collection(
        name=_COLLECTION_NAME,
        embedding_function=_EMBED_FN,
        metadata={"hnsw:space": "cosine"},
    )

    if collection.count() > 0 and not force:
        print(
            f"Collection '{_COLLECTION_NAME}' already seeded "
            f"({collection.count()} records). Use --force to re-seed."
        )
        return

    records = _load_records()
    ids = [r["id"] for r in records]
    documents = [r["document_text"] for r in records]
    metadatas = [
        {k: v for k, v in r.items() if k != "document_text"} for r in records
    ]

    print(
        f"Seeding {len(records)} records into ChromaDB "
        f"(model: all-MiniLM-L6-v2 via ONNX)..."
    )
    collection.add(ids=ids, documents=documents, metadatas=metadatas)
    print(
        f"Done. Collection '{_COLLECTION_NAME}' now has {collection.count()} records."
    )
    print(f"ChromaDB store: {_CHROMA_PATH}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the HealthCareMagic agent's ChromaDB collection.")
    parser.add_argument(
        "--force", action="store_true", help="Delete and re-seed the collection."
    )
    args = parser.parse_args()
    seed(force=args.force)

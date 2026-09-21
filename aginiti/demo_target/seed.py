"""
Seed the demo target's ChromaDB collection from the bundled
``ground_truth.json`` (25 synthetic HR records).

Embeddings are computed locally by ChromaDB's ONNX ``all-MiniLM-L6-v2`` -- no
API key, no network (after the one-time ~90MB model download).

Run standalone:
    python -m aginiti.demo_target.seed
    python -m aginiti.demo_target.seed --force   # rebuild

``main.py``'s console-script entry point also calls ``seed()`` automatically
before serving, so a fresh ``aginiti-demo-target`` run needs no separate
seeding step -- this file stays independently runnable for a forced re-seed.
"""
import argparse
import json
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2
from dotenv import load_dotenv

from ._paths import chroma_path

load_dotenv()

_COLLECTION_NAME = "hr_records_blackbox"  # must match agent.py
_GROUND_TRUTH = Path(__file__).parent / "ground_truth.json"
_EMBED_FN = ONNXMiniLM_L6_V2()


def seed(force: bool = False) -> None:
    client = chromadb.PersistentClient(path=str(chroma_path()))

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

    data = json.loads(_GROUND_TRUTH.read_text(encoding="utf-8"))
    records = data["records"]

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
    print(f"ChromaDB store: {chroma_path()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the demo target's ChromaDB collection.")
    parser.add_argument(
        "--force", action="store_true", help="Delete and re-seed the collection."
    )
    args = parser.parse_args()
    seed(force=args.force)

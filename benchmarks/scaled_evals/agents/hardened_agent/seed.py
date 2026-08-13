"""Seed hardened_agent's ChromaDB collection.

Loads ``benchmarks/scaled_evals/datasets/hardened_dataset_ingested.json``
(written by ``prepare_hardened_dataset.py`` — the ``ingested``/member half
of the split; ``hardened_dataset_held_out.json`` is never touched here, by
design — see that script's docstring) and chunks each document (see
``agent.chunk_text``) before indexing. Each CHUNK becomes its own ChromaDB
entry, not each document — unlike healthcare_agent's whole-document
indexing. Every chunk carries its parent document's ``id`` (as ``doc_id``),
``source``, and ``ops_visible`` metadata, so:

- Retrieval can be scoped per persona via a ``where`` filter on ``source``/
  ``ops_visible`` (see ``personas.py``) even though the searchable unit is
  now a chunk, not a whole document.
- Chunk-level results can be traced back to their source document —
  required for MIA/Riddle Me This's document-level (not chunk-level)
  membership ground truth, per ``plans/vanilla-target-agent.md`` §1.3/§2.

Run once before starting the agent:
    python -m benchmarks.scaled_evals.agents.hardened_agent.seed
    python -m benchmarks.scaled_evals.agents.hardened_agent.seed --force   # rebuild

Prepare the dataset first with:
    python benchmarks/scaled_evals/datasets/prepare_hardened_dataset.py
"""
import argparse
import json
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2
from dotenv import load_dotenv

from .agent import chunk_text

load_dotenv()

_CHROMA_PATH = str(Path(__file__).parent / ".chroma")
_COLLECTION_NAME = "hardened_agent_benchmark"  # must match agent.py
_DATASET = (
    Path(__file__).parent.parent.parent / "datasets" / "hardened_dataset_ingested.json"
)
_EMBED_FN = ONNXMiniLM_L6_V2()


def _load_records() -> list[dict]:
    if not _DATASET.exists():
        raise FileNotFoundError(
            f"Dataset not found at {_DATASET}. Prepare it first:\n"
            "    python benchmarks/scaled_evals/datasets/prepare_hardened_dataset.py"
        )
    return json.loads(_DATASET.read_text(encoding="utf-8"))


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
            f"({collection.count()} chunks). Use --force to re-seed."
        )
        return

    records = _load_records()

    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict] = []
    for record in records:
        chunks = chunk_text(record["document_text"])
        for chunk_index, chunk in enumerate(chunks):
            ids.append(f"{record['id']}_chunk{chunk_index:03d}")
            documents.append(chunk)
            metadatas.append({
                "doc_id": record["id"],
                "source": record["source"],
                "ops_visible": record["ops_visible"],
                "chunk_index": chunk_index,
            })

    print(
        f"Seeding {len(records)} documents ({len(ids)} chunks after splitting) "
        f"into ChromaDB (model: all-MiniLM-L6-v2 via ONNX)..."
    )
    # ChromaDB's .add() has a practical per-call batch size limit on some
    # backends — chunk the insert itself to stay well under it, same
    # defensive pattern as any bulk-insert loop, not specific to this agent.
    _BATCH = 200
    for i in range(0, len(ids), _BATCH):
        collection.add(
            ids=ids[i:i + _BATCH],
            documents=documents[i:i + _BATCH],
            metadatas=metadatas[i:i + _BATCH],
        )
    print(
        f"Done. Collection '{_COLLECTION_NAME}' now has {collection.count()} chunks "
        f"from {len(records)} documents."
    )
    print(f"ChromaDB store: {_CHROMA_PATH}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed hardened_agent's ChromaDB collection.")
    parser.add_argument(
        "--force", action="store_true", help="Delete and re-seed the collection."
    )
    args = parser.parse_args()
    seed(force=args.force)

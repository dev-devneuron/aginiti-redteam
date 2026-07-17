"""
Prepare the HealthCareMagic-1k benchmark dataset.

Downloads ``lavita/ChatDoctor-HealthCareMagic-100k`` (the exact dataset used in
the IKEA paper, arXiv:2505.15420, Table 1 — so our results are directly
comparable to the paper's reported numbers), randomly samples 1,000 rows with a
fixed seed, and writes them to ``healthcaremagic_1k.json`` next to this file.

Run standalone (does not require the reference agent or a running server):

    python benchmarks/scaled_evals/datasets/prepare_healthcare.py

Requires the optional benchmark dependencies:

    pip install -e ".[benchmarks]"

Output schema — a bare JSON **list** of records (note: this differs from the
25-record fixture ``benchmarks/dev_fixtures/datasets/ground_truth.json``, which wraps its
records in a ``{"metadata", "records"}`` object). Each record::

    {
      "id": "hcm_0001",                 # zero-padded, 1-indexed
      "document_text": "...",           # the patient consultation record
      "source": "healthcaremagic"
    }

The downloaded dataset is **not** committed to git (see ``.gitignore`` —
``benchmarks/scaled_evals/datasets/*.json``).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_HF_DATASET = "lavita/ChatDoctor-HealthCareMagic-100k"
_SAMPLE_SIZE = 1000
_SEED = 42
_OUTPUT_PATH = Path(__file__).parent / "healthcaremagic_1k.json"

# The dataset's columns are ``instruction`` / ``input`` (patient) / ``output``
# (doctor). "Patient consultation text" (spec) is most faithfully represented
# by the full exchange — the patient's description plus the doctor's response —
# which is what a medical RAG knowledge base would actually store. We combine
# both, with a robust fallback to whichever field is present.
# (Judgment call — flagged in plans/public-dataset-benchmarking-infra.md §1.6.)
def _build_document_text(row: dict) -> str:
    patient = (row.get("input") or "").strip()
    doctor = (row.get("output") or "").strip()
    if patient and doctor:
        return f"Patient inquiry:\n{patient}\n\nDoctor response:\n{doctor}"
    if patient:
        return patient
    if doctor:
        return doctor
    # Last resort — some rows may only carry the generic instruction.
    return (row.get("instruction") or "").strip()


def prepare() -> None:
    try:
        from datasets import load_dataset   
    except ImportError as exc:  # pragma: no cover - import-time guard
        raise SystemExit(
            "The 'datasets' package is required to prepare the benchmark dataset.\n"
            "Install the optional benchmark dependencies:\n"
            '    pip install -e ".[benchmarks]"'
        ) from exc

    print(f"Downloading '{_HF_DATASET}' (this can take a few minutes)...")
    dataset = load_dataset(_HF_DATASET)
    # This dataset ships a single 'train' split.
    split = dataset["train"] if "train" in dataset else dataset[next(iter(dataset))]
    total_rows = len(split)
    print(f"Downloaded {total_rows:,} rows.")

    # Deterministic sample: shuffle with a fixed seed, then take the first N.
    n = min(_SAMPLE_SIZE, total_rows)
    sampled = split.shuffle(seed=_SEED).select(range(n))

    records: list[dict] = []
    for i, row in enumerate(sampled, start=1):
        document_text = _build_document_text(row)
        if not document_text:
            continue  # skip empty rows rather than index blank documents
        records.append(
            {
                "id": f"hcm_{i:04d}",
                "document_text": document_text,
                "source": "healthcaremagic",
            }
        )

    _OUTPUT_PATH.write_text(json.dumps(records, indent=2), encoding="utf-8")

    size_mb = os.path.getsize(_OUTPUT_PATH) / (1024 * 1024)
    print("\nDone.")
    print(f"  Total rows downloaded: {total_rows:,}")
    print(f"  Rows sampled:          {len(records):,} (seed={_SEED})")
    print(f"  Output path:           {_OUTPUT_PATH}")
    print(f"  File size:             {size_mb:.2f} MB")


if __name__ == "__main__":
    prepare()

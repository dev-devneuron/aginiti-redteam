"""
Prepare the ``hardened_agent`` benchmark dataset — two real, independently-
sourced document types (see ``plans/vanilla-target-agent.md`` §2.3 for why
real data was chosen over synthesizing it: doing otherwise would quietly
reintroduce the same circularity problem this project has spent real effort
getting away from — "did we write documents that happen to be easy to
leak?" is the same objection as "did we write the attack and the target").

Each type is sampled into ONE pool, then randomly split into an
``ingested`` (member) set and a ``held_out`` (non-member) set from that same
pool — not two independently-sourced pools. This is what makes the held-out
set valid ground truth for future membership-inference work (Riddle Me
This): a non-member set that's superficially different from the member set
lets an attack "succeed" by detecting distribution shift, not real
membership. See ``plans/vanilla-target-agent.md`` §1.3.

Sources (both verified live, not assumed from documentation):

- **Legal / policy documents**: CUAD v1 (Contract Understanding Atticus
  Dataset) — 510 real commercial legal contracts, CC BY 4.0, via
  HuggingFace (``theatticusproject/cuad-qa``). Loaded via the
  auto-converted ``refs/convert/parquet`` revision — the dataset's default
  branch uses a legacy Python loading script no longer supported by current
  ``datasets`` versions (``RuntimeError: Dataset scripts are no longer
  supported``). This is not a workaround; HuggingFace auto-generates this
  parquet branch specifically to keep such datasets loadable, and it's the
  correct current path, verified by actually loading it.
- **Support-ticket / complaint documents**: the CFPB Consumer Complaint
  Database — real consumer complaint narratives published by the US
  Consumer Financial Protection Bureau. Pulled directly from CFPB's own
  public API (``consumerfinance.gov/.../api/v1/``), NOT the
  ``CFPB/consumer-finance-complaints`` HuggingFace mirror, which has the
  identical legacy-loading-script problem as CUAD's default branch — going
  straight to the primary source sidesteps that entirely, and is the more
  authoritative source anyway. **Honest caveat, not hidden**: CFPB removes
  direct PII from narratives before publishing (partial ``XXXX`` masking is
  visible in real responses) — a genuine characteristic of the source, and
  arguably makes it *more* representative of a real intake-scrubbed
  enterprise ticket system than raw unscrubbed text would be, not less.

Output schema — a bare JSON list per file, each record::

    {
      "id": "cuad_0001" | "cfpb_0001",
      "document_text": "...",
      "source": "cuad" | "cfpb",
      "ops_visible": true | false   # in the `ops` persona's cross-domain subset?
    }

``hardened_dataset_ingested.json`` is what ``hardened_agent/seed.py`` loads.
``hardened_dataset_held_out.json`` is NEVER ingested — held for future
membership-inference (Riddle Me This) ground truth. Both gitignored, not
committed — same convention as ``healthcaremagic_1k.json``.

Run standalone:

    python benchmarks/scaled_evals/datasets/prepare_hardened_dataset.py

Requires the optional benchmark dependencies (``pip install -e ".[benchmarks]"``)
for CUAD (uses the ``datasets`` library); the CFPB fetch uses ``requests``
directly (already a hard dependency of this project) against CFPB's public
API, no extra package needed.
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_SEED = 42
_CUAD_TARGET_UNIQUE = 400        # CUAD has ~510 unique contracts total (a hard
                                  # ceiling) — sampling below that ceiling, not at it,
                                  # leaves room for the shuffle to actually vary.
_CFPB_TARGET_UNIQUE = 400        # CFPB has millions available; matched to CUAD's
                                  # count for a balanced two-domain corpus, not
                                  # because 400 is independently meaningful.
_INGESTED_RATIO = 0.7            # 70% ingested / 30% held out, per type.
_OPS_VISIBLE_FRACTION = 0.2      # fraction of EACH type's ingested set also
                                  # visible to the `ops` persona (aggregation-risk
                                  # case — see plan §2.4). Held-out records never
                                  # get this flag; they're never ingested at all.

_INGESTED_OUTPUT = Path(__file__).parent / "hardened_dataset_ingested.json"
_HELD_OUT_OUTPUT = Path(__file__).parent / "hardened_dataset_held_out.json"

_CFPB_API = "https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/"
_CFPB_MIN_NARRATIVE_CHARS = 100  # filters out complaints that are almost entirely
                                  # XXXX-masked, leaving too little real text to
                                  # be a meaningful document.


# ---------------------------------------------------------------------------
# CUAD — legal/policy documents
# ---------------------------------------------------------------------------
def _load_cuad(target_unique: int, seed: int) -> list[dict]:
    try:
        from datasets import load_dataset
    except ImportError as exc:  # pragma: no cover - import-time guard
        raise SystemExit(
            "The 'datasets' package is required to prepare CUAD.\n"
            "Install the optional benchmark dependencies:\n"
            '    pip install -e ".[benchmarks]"'
        ) from exc

    print("Downloading CUAD v1 (theatticusproject/cuad-qa, parquet revision)...")
    # revision="refs/convert/parquet": the default branch's loading script is
    # no longer supported by current `datasets` versions — see module
    # docstring. Non-streaming load (not streaming=True): streaming mode's
    # tensor-sharing code path imports torch, which this project explicitly
    # never depends on (CLAUDE.md's locked embedding architecture) and which
    # can fail to load its native DLLs on some Windows setups regardless —
    # verified live. Non-streaming load doesn't hit that path.
    ds = load_dataset(
        "theatticusproject/cuad-qa", split="train", revision="refs/convert/parquet"
    )

    # CUAD-QA is one row per (contract, clause-question) pair — many rows
    # share the same contract. Dedupe by title to get unique contracts,
    # keeping each title's `context` (the full contract text).
    seen_titles: dict[str, str] = {}
    for row in ds:
        title = row["title"]
        if title not in seen_titles:
            seen_titles[title] = row["context"]

    unique_contracts = list(seen_titles.items())
    print(f"  {len(unique_contracts)} unique contracts found "
          f"(from {len(ds)} question rows).")

    rng = random.Random(seed)
    rng.shuffle(unique_contracts)
    sampled = unique_contracts[:target_unique]

    return [
        {"id": f"cuad_{i:04d}", "document_text": text, "source": "cuad"}
        for i, (title, text) in enumerate(sampled, start=1)
    ]


# ---------------------------------------------------------------------------
# CFPB — support-ticket/complaint documents
# ---------------------------------------------------------------------------
def _load_cfpb(target_unique: int, seed: int, timeout: int = 30) -> list[dict]:
    # Over-fetch: has_narrative=true already filters to complaints with a
    # public narrative, but some remaining narratives are almost entirely
    # XXXX-masked (see module docstring) and get dropped below — fetch a
    # buffer so the final sample still hits target_unique after that filter.
    fetch_size = target_unique * 3
    print(f"Fetching {fetch_size} candidate complaints from CFPB's public API...")
    resp = requests.get(
        _CFPB_API,
        params={"size": fetch_size, "has_narrative": "true"},
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    hits = data.get("hits", {}).get("hits", [])
    print(f"  {len(hits)} candidates returned "
          f"(of {data.get('hits', {}).get('total', {}).get('value', '?')} total available).")

    candidates: list[dict] = []
    for hit in hits:
        source = hit.get("_source", {})
        narrative = (source.get("complaint_what_happened") or "").strip()
        if len(narrative) < _CFPB_MIN_NARRATIVE_CHARS:
            continue  # almost entirely masked, or empty despite has_narrative=true
        candidates.append({
            "complaint_id": source.get("complaint_id", hit.get("_id")),
            "document_text": narrative,
        })

    rng = random.Random(seed)
    rng.shuffle(candidates)
    sampled = candidates[:target_unique]

    return [
        {"id": f"cfpb_{i:04d}", "document_text": c["document_text"], "source": "cfpb"}
        for i, c in enumerate(sampled, start=1)
    ]


# ---------------------------------------------------------------------------
# Split + ops-visibility tagging
# ---------------------------------------------------------------------------
def _split_ingested_held_out(
    pool: list[dict], ingested_ratio: float, seed: int
) -> tuple[list[dict], list[dict]]:
    """Randomly partition ONE pool into (ingested, held_out) — not two
    independently-sourced pools. See module docstring for why this
    mechanism, not the two lists' contents, is what makes held_out valid
    membership-inference ground truth."""
    shuffled = list(pool)
    random.Random(seed).shuffle(shuffled)
    split_at = round(len(shuffled) * ingested_ratio)
    return shuffled[:split_at], shuffled[split_at:]


def _tag_ops_visibility(ingested: list[dict], fraction: float, seed: int) -> None:
    """Mutates `ingested` in place, flagging a random fraction as visible to
    the `ops` persona (the aggregation-risk case — plan §2.4). Only called
    on the ingested set; held_out records are never in the store at all, so
    persona visibility doesn't apply to them."""
    rng = random.Random(seed)
    n_ops_visible = round(len(ingested) * fraction)
    ops_indices = set(rng.sample(range(len(ingested)), n_ops_visible)) if ingested else set()
    for i, record in enumerate(ingested):
        record["ops_visible"] = i in ops_indices


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def prepare(force: bool = False) -> None:
    # Idempotency guard (a real bug found running this in Docker Compose):
    # unlike CUAD, CFPB's public API is a live, daily-
    # updating feed, not a static snapshot — a re-run is NOT guaranteed to
    # reproduce the same sample even with the same _SEED, because the input
    # pool itself can differ. `seed.py` skips re-embedding if the ChromaDB
    # collection already has content, but this script previously had no
    # matching guard — since docker-compose.yml's `hardened_agent` service
    # depends on `prepare-hardened` -> `seed-hardened` every time it starts,
    # a plain `docker compose up` could silently regenerate the dataset
    # files (new CFPB sample) while `seed-hardened` skips reseeding (old
    # ChromaDB content) — ground truth and what's actually embedded would
    # then quietly disagree. Skip regeneration by default if both output
    # files already exist; pass --force to deliberately rebuild (and then
    # re-seed to match, via `seed.py --force`).
    if not force and _INGESTED_OUTPUT.exists() and _HELD_OUT_OUTPUT.exists():
        print(f"{_INGESTED_OUTPUT.name} and {_HELD_OUT_OUTPUT.name} already exist "
              f"— skipping regeneration (pass --force to rebuild; CFPB's API is a "
              f"live feed, so a rebuild is not guaranteed to reproduce the same "
              f"sample — re-seed with seed.py --force afterward if you do this).")
        return

    cuad_pool = _load_cuad(_CUAD_TARGET_UNIQUE, _SEED)
    cfpb_pool = _load_cfpb(_CFPB_TARGET_UNIQUE, _SEED)

    cuad_ingested, cuad_held_out = _split_ingested_held_out(cuad_pool, _INGESTED_RATIO, _SEED)
    cfpb_ingested, cfpb_held_out = _split_ingested_held_out(cfpb_pool, _INGESTED_RATIO, _SEED + 1)

    # Different seed offset per type for ops-visibility sampling so the same
    # seed doesn't correlate which records get picked across the two types.
    _tag_ops_visibility(cuad_ingested, _OPS_VISIBLE_FRACTION, _SEED + 2)
    _tag_ops_visibility(cfpb_ingested, _OPS_VISIBLE_FRACTION, _SEED + 3)

    ingested = cuad_ingested + cfpb_ingested
    held_out = cuad_held_out + cfpb_held_out
    # held_out records never touch the store — no ops_visible field needed,
    # but set it False explicitly so the schema is uniform for consumers
    # that don't branch on which file they're reading.
    for record in held_out:
        record["ops_visible"] = False

    _INGESTED_OUTPUT.write_text(json.dumps(ingested, indent=2), encoding="utf-8")
    _HELD_OUT_OUTPUT.write_text(json.dumps(held_out, indent=2), encoding="utf-8")

    n_ops_cuad = sum(1 for r in cuad_ingested if r["ops_visible"])
    n_ops_cfpb = sum(1 for r in cfpb_ingested if r["ops_visible"])
    print("\nDone.")
    print(f"  CUAD:  {len(cuad_ingested)} ingested ({n_ops_cuad} ops-visible), {len(cuad_held_out)} held out")
    print(f"  CFPB:  {len(cfpb_ingested)} ingested ({n_ops_cfpb} ops-visible), {len(cfpb_held_out)} held out")
    print(f"  Total: {len(ingested)} ingested, {len(held_out)} held out")
    print(f"  Wrote: {_INGESTED_OUTPUT}")
    print(f"  Wrote: {_HELD_OUT_OUTPUT}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true",
                        help="Rebuild even if the dataset files already exist. "
                             "CFPB's API is a live feed, so this is NOT guaranteed "
                             "to reproduce the same sample as before -- re-seed "
                             "hardened_agent with seed.py --force afterward if you do this.")
    args = parser.parse_args()
    prepare(force=args.force)

"""
Hardened-agent MIA runner — run InterrogationAttack against ``hardened_agent``
(port 8004), authenticated as ONE persona per invocation. The MIA parallel
of ``scripts/run_ikea_hardened.py`` (IKEA/DRA); mirrors its CLI
conventions (one persona per command, `/config` toggle-state recording,
timestamped self-describing output filenames) so both attacks against this
target are operated the same way.

Usage:
    python scripts/run_interrogation_hardened.py --persona support
    python scripts/run_interrogation_hardened.py --persona legal --queries 30
    python scripts/run_interrogation_hardened.py --persona ops --force-recalibrate

Document selection is automatic, from the prepared ingested/held-out
dataset (``benchmarks/scaled_evals/datasets/hardened_dataset_{ingested,held_out}.json``
— run ``prepare_hardened_dataset.py`` first if these don't exist yet):

- ``legal``   — member candidates from CUAD (ingested), non-member candidate
                from CUAD (held-out), one CFPB candidate (out-of-scope —
                tests the disjoint RBAC boundary), calibration reference
                set from CUAD held-out.
- ``support`` — mirror image: CFPB member/non-member/reference, one CUAD
                candidate for the disjoint-boundary test.
- ``ops``     — member candidates from BOTH domains' ops_visible-tagged
                ingested docs, one non-ops-visible ingested doc (tests
                whether ops's narrower *subset* boundary holds, not just
                the legal/support disjoint split), one held-out doc.

Selection is **deterministic** (sorted by document id, not random) so the
exact same command reproduces the exact same document set — see the
module-level constants below for the exact counts, or override via CLI
flags.

Documents are length-filtered (``--max-doc-chars``, default 4000) before
selection — CUAD contracts run to a median ~33K characters (up to 335K),
which would make each of MIA's n_probe_questions retrieval-summary/probe-
generation/shadow-LLM calls carry the full document text at real cost and
latency. This keeps a first real run tractable; rerun with a higher cap
(or a specific hand-picked document set, editing the constants below) once
initial results look sane.
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

from aginiti.attacks.mia import InterrogationAttack

# ---------------------------------------------------------------------------
# Canonical attack-side parameters
# ---------------------------------------------------------------------------
AGENT_URL = os.getenv("HARDENED_AGENT_URL", "http://localhost:8004")
INGESTED_PATH = "benchmarks/scaled_evals/datasets/hardened_dataset_ingested.json"
HELD_OUT_PATH = "benchmarks/scaled_evals/datasets/hardened_dataset_held_out.json"
LLM_PROVIDER = "gemini/gemini-3.5-flash"
SHADOW_LLM_PROVIDER = "groq/llama-3.3-70b-versatile"  # deliberately different family, see
                                                        # InterrogationAttack's shadow_llm_provider docstring
DEFAULT_QUERIES = 15  # paper default is 30; starting smaller for the first real run
                       # against this target -- see plans/mia-interrogation-attack.md
                       # and the methodology doc's own n-ablation ("n=5 already beats
                       # baselines, diminishing returns after ~15-20")
DEFAULT_N_REFERENCE = 5
DEFAULT_N_MEMBER_CANDIDATES = 2
DEFAULT_N_NON_MEMBER_CANDIDATES = 1
DEFAULT_MAX_DOC_CHARS = 4000

PERSONAS = ("legal", "support", "ops")
_PERSONA_SOURCE = {"legal": "cuad", "support": "cfpb"}  # ops handled specially

_RESULTS_DIR = Path(__file__).parent.parent / "benchmarks" / "scaled_evals" / "results"


def _api_key_for(persona: str) -> str:
    env_var = f"HARDENED_AGENT_{persona.upper()}_API_KEY"
    key = os.environ.get(env_var)
    if not key:
        raise SystemExit(
            f"{env_var} is not set (repo-root .env or shell env). "
            f"See benchmarks/scaled_evals/agents/hardened_agent/README.md."
        )
    return key


def _key_for_llm(model: str) -> str:
    provider = model.split("/", 1)[0].lower()
    env_var = {"gemini": "GEMINI_API_KEY", "groq": "GROQ_API_KEY"}.get(provider)
    if env_var is None:
        raise SystemExit(f"No known API key env var for provider {provider!r}")
    key = os.environ.get(env_var)
    if not key:
        raise SystemExit(f"{env_var} not set in .env")
    return key


def _shadow_api_keys(model: str) -> list[str] | None:
    """
    Multi-key rotation for the shadow LLM (added 2026-08-12) — Stage B call
    volume (documents x n_probe_questions) dominates total run time and is
    the first thing to hit a free-tier rate limit, so several rotating keys
    reduce how often a run actually blocks on it (see
    BaseAttack._init_llm's api_keys docstring for the rotation mechanics).

    Reads GROQ_API_KEY_1..GROQ_API_KEY_9 from the environment (stops at the
    first gap) for a groq/* shadow model. Falls back to None (single-key
    path via _key_for_llm) if no numbered keys are set, or if the shadow
    model isn't groq/* -- this is intentionally not provider-generic yet,
    since GROQ_API_KEY_N is the only multi-key convention actually in use.
    """
    provider = model.split("/", 1)[0].lower()
    if provider != "groq":
        return None
    keys = []
    i = 1
    while True:
        key = os.environ.get(f"GROQ_API_KEY_{i}")
        if not key:
            break
        keys.append(key)
        i += 1
    return keys or None


def _live_toggle_state(agent_url: str) -> dict:
    try:
        resp = requests.get(f"{agent_url}/config", timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        print(f"WARNING: could not fetch {agent_url}/config ({exc}) -- "
              f"run metadata won't record the target's actual toggle state.")
        return {}


def _toggle_tag(config: dict) -> str:
    if not config:
        return "cfg-unknown"

    def _flag(key: str, short: str) -> str:
        return f"{short}-{'on' if config.get(key) else 'off'}"

    return "_".join([
        _flag("rbac_enabled", "rbac"),
        _flag("rate_limit_enabled", "rl"),
        _flag("redaction_enabled", "rd"),
        _flag("memory_enabled", "mem"),
    ])


def _load_docs(max_chars: int) -> tuple[list[dict], list[dict]]:
    ingested = json.loads(Path(INGESTED_PATH).read_text(encoding="utf-8"))
    held_out = json.loads(Path(HELD_OUT_PATH).read_text(encoding="utf-8"))
    ingested = [d for d in ingested if len(d["document_text"]) <= max_chars]
    held_out = [d for d in held_out if len(d["document_text"]) <= max_chars]
    return ingested, held_out


def _pick(docs: list[dict], n: int, exclude_ids: set) -> list[dict]:
    """Deterministic selection: sorted by id, first N not already used."""
    candidates = sorted((d for d in docs if d["id"] not in exclude_ids), key=lambda d: d["id"])
    if len(candidates) < n:
        raise SystemExit(
            f"Only {len(candidates)} eligible documents available, need {n}. "
            f"Try a higher --max-doc-chars."
        )
    return candidates[:n]


def _as_attack_doc(d: dict) -> dict:
    return {"id": d["id"], "text": d["document_text"]}


def _select_documents(
    persona: str, max_chars: int, n_reference: int,
    n_member: int, n_non_member: int, include_cross_domain: bool,
) -> tuple[list[dict], list[dict], list[str]]:
    """
    Returns (candidates, reference_docs, notes) where each doc dict is
    {"id", "text"} and notes describes what each candidate is expected to
    show, for the printed/saved run summary.
    """
    ingested, held_out = _load_docs(max_chars)
    used_ids: set = set()
    candidates: list[dict] = []
    notes: list[str] = []

    if persona in ("legal", "support"):
        own_source = _PERSONA_SOURCE[persona]
        other_source = "cfpb" if own_source == "cuad" else "cuad"

        own_ingested = [d for d in ingested if d["source"] == own_source]
        own_held_out = [d for d in held_out if d["source"] == own_source]
        other_ingested = [d for d in ingested if d["source"] == other_source]

        members = _pick(own_ingested, n_member, used_ids)
        used_ids |= {d["id"] for d in members}
        for d in members:
            candidates.append(_as_attack_doc(d))
            notes.append(f"{d['id']}: real {own_source} member, in {persona}'s scope -> expect MEMBER")

        non_members = _pick(own_held_out, n_non_member, used_ids)
        used_ids |= {d["id"] for d in non_members}
        for d in non_members:
            candidates.append(_as_attack_doc(d))
            notes.append(f"{d['id']}: held-out {own_source} doc, never ingested -> expect NON-MEMBER")

        if include_cross_domain:
            cross = _pick(other_ingested, 1, used_ids)
            used_ids |= {d["id"] for d in cross}
            for d in cross:
                candidates.append(_as_attack_doc(d))
                notes.append(
                    f"{d['id']}: real {other_source} member, OUT of {persona}'s scope "
                    f"-> expect NON-MEMBER if RBAC holds (a MEMBER result here is an RBAC-bypass finding)"
                )

        reference_pool = [d for d in own_held_out if d["id"] not in used_ids]
        reference = _pick(reference_pool, n_reference, used_ids)

    elif persona == "ops":
        ops_visible_cuad = [d for d in ingested if d["source"] == "cuad" and d["ops_visible"]]
        ops_visible_cfpb = [d for d in ingested if d["source"] == "cfpb" and d["ops_visible"]]
        non_ops_visible = [d for d in ingested if not d["ops_visible"]]

        n_each = max(1, n_member // 2)
        for pool, src in ((ops_visible_cuad, "cuad"), (ops_visible_cfpb, "cfpb")):
            picked = _pick(pool, n_each, used_ids)
            used_ids |= {d["id"] for d in picked}
            for d in picked:
                candidates.append(_as_attack_doc(d))
                notes.append(f"{d['id']}: ops-visible {src} doc, in ops's subset -> expect MEMBER")

        subset_test = _pick(non_ops_visible, n_non_member, used_ids)
        used_ids |= {d["id"] for d in subset_test}
        for d in subset_test:
            candidates.append(_as_attack_doc(d))
            notes.append(
                f"{d['id']}: real member ({d['source']}), NOT ops-visible "
                f"-> expect NON-MEMBER if ops's subset boundary holds "
                f"(a MEMBER result here is a subset-boundary-bypass finding)"
            )

        true_negative = _pick(held_out, 1, used_ids)
        used_ids |= {d["id"] for d in true_negative}
        for d in true_negative:
            candidates.append(_as_attack_doc(d))
            notes.append(f"{d['id']}: held-out doc, never ingested -> expect NON-MEMBER")

        reference_pool = [d for d in held_out if d["id"] not in used_ids]
        reference = _pick(reference_pool, n_reference, used_ids)

    else:
        raise SystemExit(f"Unknown persona: {persona!r}")

    return candidates, [_as_attack_doc(d) for d in reference], notes


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--persona", required=True, choices=PERSONAS)
    parser.add_argument("--queries", type=int, default=DEFAULT_QUERIES,
                        help=f"n_probe_questions per document (default: {DEFAULT_QUERIES}; "
                             f"paper default is 30).")
    parser.add_argument("--n-reference", type=int, default=DEFAULT_N_REFERENCE)
    parser.add_argument("--n-member-candidates", type=int, default=DEFAULT_N_MEMBER_CANDIDATES)
    parser.add_argument("--n-non-member-candidates", type=int, default=DEFAULT_N_NON_MEMBER_CANDIDATES)
    parser.add_argument("--max-doc-chars", type=int, default=DEFAULT_MAX_DOC_CHARS)
    parser.add_argument("--no-cross-domain-candidate", action="store_true",
                        help="Skip the out-of-scope RBAC-boundary candidate (legal/support only).")
    parser.add_argument("--force-recalibrate", action="store_true")
    parser.add_argument("--agent-url", default=AGENT_URL)
    args = parser.parse_args()

    api_key = _api_key_for(args.persona)
    endpoint_kwargs = {"headers": {"Authorization": f"Bearer {api_key}"}}

    live_config = _live_toggle_state(args.agent_url)
    toggle_tag = _toggle_tag(live_config)
    if live_config:
        print(f"Target's actual toggle state (via /config): {live_config}")

    candidates, reference_docs, notes = _select_documents(
        persona=args.persona,
        max_chars=args.max_doc_chars,
        n_reference=args.n_reference,
        n_member=args.n_member_candidates,
        n_non_member=args.n_non_member_candidates,
        include_cross_domain=not args.no_cross_domain_candidate,
    )

    print(f"\n=== Document selection for persona={args.persona!r} ===")
    for note in notes:
        print(f"  {note}")
    print(f"  ({len(reference_docs)} calibration reference docs, not itemized above)")
    print()

    shadow_keys = _shadow_api_keys(SHADOW_LLM_PROVIDER)
    if shadow_keys:
        print(f"Shadow LLM: rotating across {len(shadow_keys)} GROQ_API_KEY_N keys.")

    attack = InterrogationAttack(
        target_url=args.agent_url,
        llm_provider=LLM_PROVIDER,
        api_key=_key_for_llm(LLM_PROVIDER),
        non_member_reference_docs=reference_docs,
        shadow_llm_provider=SHADOW_LLM_PROVIDER,
        shadow_llm_api_key=_key_for_llm(SHADOW_LLM_PROVIDER),
        shadow_llm_api_keys=shadow_keys,
        n_probe_questions=args.queries,
        endpoint_kwargs=endpoint_kwargs,
    )

    started_at = datetime.now(timezone.utc)
    findings = attack.execute(documents=candidates, force_recalibrate=args.force_recalibrate)
    finished_at = datetime.now(timezone.utc)
    duration_seconds = (finished_at - started_at).total_seconds()

    print("\n" + "=" * 70)
    print(f"RESULT ({args.persona}): {len(findings)}/{len(candidates)} candidates confirmed as members")
    for f in findings:
        print(f"  MEMBER CONFIRMED: {f.leaked_content}")
    for r in attack.non_member_results:
        print(f"  non-member: {r['id']} (score={r['score']:.4f}, threshold={r['threshold']:.4f})")
    print(f"  duration: {duration_seconds:.1f}s")
    print(f"  LLM calls -- attacker: {attack._llm_call_count}, shadow: {attack._shadow_llm_call_count}")
    print("=" * 70)

    run_id = started_at.strftime("%Y%m%dT%H%M%SZ")
    output = _RESULTS_DIR / (
        f"mia_hardened_{args.persona}_{toggle_tag}_{args.queries}q_{run_id}.json"
    )
    report = {
        "run": {
            "attack": "mia_interrogation",
            "persona": args.persona,
            "target_toggle_state": live_config or "unknown (config fetch failed)",
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": duration_seconds,
            "target_url": args.agent_url,
            "llm_provider": LLM_PROVIDER,
            "shadow_llm_provider": SHADOW_LLM_PROVIDER,
            "n_probe_questions": args.queries,
            "lambda_unk": attack.lambda_unk,
            "fpr_target": attack.fpr_target,
            "n_non_member_reference_docs": len(reference_docs),
            "n_candidates_tested": len(candidates),
            "n_confirmed_members": len(findings),
            "n_non_members": len(attack.non_member_results),
            "attacker_llm_calls": attack._llm_call_count,
            "shadow_llm_calls": attack._shadow_llm_call_count,
            "candidate_selection_notes": notes,
        },
        "findings": [asdict(f) for f in findings],
        "non_member_results": attack.non_member_results,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nSaved full results to {output}")


if __name__ == "__main__":
    main()

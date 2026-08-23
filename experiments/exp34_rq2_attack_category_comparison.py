"""exp34 -- RQ2: which `attack_category` methodology performs best against
`hardened_agent`'s full production-hardened defense posture (the same
8-defense-layer stack exp33 ran against), and does the adaptive planner's
own operator preference (when every category is available at once) track
which category actually pays off?

============================================================================
WHY THIS EXISTS: exp29/32/33 all answer "does Aginiti's adaptive planner
beat Random/Static enumeration" (RQ1) -- a POLICY comparison, category held
fixed (the whole library, mixed). This is a different, complementary
question: holding policy FIXED (AginitiPolicy throughout -- this is not a
policy comparison), does the attack METHODOLOGY itself matter? Built
directly on top of `OperatorLibrary.by_category()` (added this session,
`aginiti/operators/library.py`) -- this experiment is also that method's
first real, live, load-bearing use, not just its unit tests.

============================================================================
DESIGN, LOCKED BEFORE ANY LIVE QUERY:

Two phases, run back to back per persona (legal/support/ops), fresh
hardened_agent restart before EVERY trial (same discipline as every prior
experiment here -- conversation memory is per-persona/per-server-process,
so a stale restart would contaminate results, see docs/
QUICKSTART_HARDENED_AGENT.md's own documented gotcha):

**Phase A -- isolated, exhaustive per-category runs.** For each
`attack_category` this persona's full operator library actually has real
(non-fixture) operators in -- filtered via `OperatorLibrary.by_category()`,
the exact mechanism this experiment exists partly to exercise -- run ONE
campaign using ONLY that category's operators. Budget = sum(op.cost_prompts
for op in category) + 5 headroom (small relative to encoding_attack's 26
or multi_step_chain's 52, proportionally larger for the four 1-operator
categories) -- enough to let AginitiPolicy attempt essentially everything
the category has, not an arbitrary fixed number that would favor
cheap-many-operator categories over expensive-few-operator ones or vice
versa. `stop_on_mission_success=False` DELIBERATELY, unlike every RQ1
script here -- this experiment wants the category's FULL exhaustive
performance (how many of its own operators land, not just "got one hit and
stopped"), not early-stopping efficiency (RQ1's own concern, not this
one's).

Known, disclosed limitation, not hidden: a `ClassPrecondition`-gated
operator within a category can depend on a claim a DIFFERENT category's
operator would normally produce (e.g. an escalate-after-disclosure
follow-up). Isolated to one category, such an operator may never become
eligible even though it structurally belongs to that category -- this
experiment does not claim 100% of a category's nominal operator count
always gets a real attempt, only reports how many actually did
(`operators_executed` in every result row, directly comparable against
the category's own `n_operators`).

**Phase B -- planner category-preference, combined library.** One
campaign per persona using the SAME full library exp32/33 use (generic
target-agnostic packs + `build_hardened_agent_library` + `hardened_deep_
attack_operators`), budget=60 (exp33's own budget, same library size),
`stop_on_mission_success=False` again (want the planner's full
across-budget behavior, not just its first pick). For every step in the
resulting `decision_log`, the CHOSEN operator's category (via
`operator_primary_family()`, the SAME canonical classifier `by_category()`
itself uses -- no second, potentially-drifting definition of "this
operator's category" anywhere in this script) is tallied, cross-referenced
against `execution_log` for whether that specific pick actually confirmed
anything. This answers a genuinely different question from Phase A: not
"how good IS each category" but "does Aginiti's own utility function
actually gravitate toward the categories that are good, when it has to
choose among all of them under one shared, scarce budget."

Deep-attack query budgets: SAME reduced "staged verification" settings
exp32/33 established (IKEA max_queries=8, SECRET phase1_n_iter=3/n_cand=2/
max_queries=6, MIA n_probe_questions=3) -- not scaled up, for the same
reason exp33 gives (proven working at these settings; SECRET is
structurally input-filter-blocked regardless of budget per exp33's own
pre-launch finding, so more budget for it specifically would not change
the outcome).

Cost/time note, stated up front, honestly: `multi_step_chain` is only 3
operators (hardened_ikea_exfiltration/hardened_secret_exfiltration/
hardened_mia_membership -- cost_prompts 20/16/16) but each makes many real
internal LLM/target calls; at `stop_on_mission_success=False` all 3 run to
completion in every persona's Phase-A trial for that category (budget=57
comfortably fits all three), by far the slowest and most expensive part of
this experiment -- 9 full deep-attack executions guaranteed from Phase A
alone, more possible from Phase B if the planner picks them there too. The
other 7 categories are cheap, fast template/heuristic probes by
comparison. Scoped this way deliberately (full 3-persona coverage, not
reduced) -- see this session's own design discussion for why.

SECRET is EXPECTED to underperform here specifically (not a surprise if it
does): exp33's own pre-launch live testing found the input filter
structurally blocks SECRET's core "transcribe verbatim" mechanism
regardless of phrasing, while IKEA's benign-looking queries evade it. This
prediction is stated here, before the run, exactly so the analysis
afterward can be checked against it rather than rationalized after the
fact -- if multi_step_chain's own finding rate is low, part of the
"why" is already known and disclosed, not a mystery to explain away.

Usage:
    python experiments/exp34_rq2_attack_category_comparison.py
"""
from __future__ import annotations

import json
import logging
import os
import sys
import traceback
from pathlib import Path

sys.path.insert(0, ".")

from dotenv import load_dotenv

load_dotenv()

# Staged-verification query-budget overrides -- SAME settings exp32/33
# proved sane (see module docstring's "Deep-attack query budgets" note).
# Set BEFORE importing hardened_deep_attack_operators (its module-level
# constants read these once, at import time).
os.environ.setdefault("IKEA_OPERATOR_MAX_QUERIES", "8")
os.environ.setdefault("SECRET_OPERATOR_PHASE1_N_ITER", "3")
os.environ.setdefault("SECRET_OPERATOR_PHASE1_N_CAND", "2")
os.environ.setdefault("SECRET_OPERATOR_MAX_QUERIES", "6")
os.environ.setdefault("MIA_OPERATOR_N_PROBE_QUESTIONS", "3")

from aginiti.adapters.hardened_agent_adapter import HardenedAgentAdapter
from aginiti.adapters.scaled_evals_ground_truth import FuzzyDisclosureIndex, VerbatimDisclosureIndex
from aginiti.core.campaign import run_campaign
from aginiti.core.graph.attack_category import ALL_CATEGORIES, CATEGORY_TITLES, OFFENSIVE_CATEGORIES, operator_primary_family
from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.core.planner.aginiti_planner import AginitiPlanner
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.operators.access_control_layer_probe import access_control_layer_probe_operators
from aginiti.operators.adaptive_followups import adaptive_followup_operators
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.encoding_variants import build_encoding_evasion_operators
from aginiti.operators.hardened_agent_definitions import build_hardened_agent_library
from aginiti.operators.hardened_deep_attack_operators import hardened_deep_attack_operators
from aginiti.operators.library import Operator, OperatorLibrary
from aginiti.operators.output_filter_evasion import output_filter_evasion_operators
from aginiti.operators.redaction_format_evasion import redaction_format_evasion_operators
from aginiti.operators.session_isolation_probe import session_isolation_probe_operators

from experiments._target_lifecycle import restart_target, stop_target

_ROOT = Path(__file__).parent.parent
_DATASETS = _ROOT / "benchmarks" / "scaled_evals" / "datasets"
_RESULTS_DIR = _ROOT / "experiments" / "results" / "runs_exp34_rq2_attack_category_comparison"
_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

_PERSONAS = ("legal", "support", "ops")
_TIMEOUT = 180.0
_SERVER_RESTART_TIMEOUT = 60.0
_CATEGORY_HEADROOM = 5
_COMBINED_BUDGET = 60  # matches exp33's own budget for the same full library


def _configure_logging() -> None:
    fmt = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(_RESULTS_DIR / "exp34_run.log", mode="a", encoding="utf-8")
    file_handler.setFormatter(fmt)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    aginiti_logger = logging.getLogger("aginiti")
    aginiti_logger.setLevel(logging.INFO)
    aginiti_logger.addHandler(file_handler)
    aginiti_logger.addHandler(console_handler)


def _full_library(persona: str, hardened_index) -> OperatorLibrary:
    """Every operator this project currently wires against hardened_agent
    for this persona -- the SAME composition exp32/33 use, so this
    experiment's per-category results are directly comparable to those
    prior runs' own findings, not a new, incomparable library."""
    generic = [
        *access_control_layer_probe_operators(), *adaptive_followup_operators(),
        *data_exposure_operators(), *build_encoding_evasion_operators(),
        *output_filter_evasion_operators(), *redaction_format_evasion_operators(),
        *session_isolation_probe_operators(),
    ]
    hardened_specific = build_hardened_agent_library(persona, hardened_index)
    deep = hardened_deep_attack_operators(persona, mia_n_reference=3)
    return OperatorLibrary([*generic, *hardened_specific, *deep])


def _success_keys(op: Operator) -> set[str]:
    """Same convention scripts/run_campaign.py's own dynamic-mission
    logic already established -- deep-attack operators declare exactly
    one claim_key; prompt operators may declare more than one
    effects_success ClaimEffect."""
    if op.kind == "deep_attack":
        return {op.claim_key} if op.claim_key else set()
    return {e.key for e in op.effects_success}


def _distinct_findings(ssg: SecurityStateGraph) -> int:
    """Same method exp32/33 established -- counts claims tagged with a
    real security_boundary, the general confirmed-finding proxy used
    throughout this project's RQ1 experiments."""
    return sum(1 for claim in ssg.claims if ssg.claim_boundary.get(claim.key) is not None)


def _adapter(persona: str, hardened_index, fuzzy_index) -> HardenedAgentAdapter:
    api_key = os.environ[f"HARDENED_AGENT_{persona.upper()}_API_KEY"]
    return HardenedAgentAdapter(persona=persona, api_key=api_key, disclosure_index=hardened_index,
                                 fuzzy_disclosure_index=fuzzy_index, timeout=_TIMEOUT)


def _policy() -> AginitiPolicy:
    return AginitiPolicy(AginitiPlanner(enable_family_diversification=True,
                                         enable_hypothesis_escalation_bonus=True,
                                         enable_technique_cluster_diversification=True))


def _run_category_trial(persona: str, category: str, ops: list[Operator],
                         hardened_index, fuzzy_index) -> dict:
    label = f"hardened_agent_{persona}__category_{category}"
    print(f"\n{'=' * 78}\n{label}  (n_operators={len(ops)})\n{'=' * 78}")

    restart_target("hardened_agent", timeout=_SERVER_RESTART_TIMEOUT)

    adapter = _adapter(persona, hardened_index, fuzzy_index)
    library = OperatorLibrary(ops)
    budget = sum(op.cost_prompts for op in ops) + _CATEGORY_HEADROOM
    criteria = tuple(sorted({key for op in ops for key in _success_keys(op)}))
    mission = Mission(
        goal=f"Isolated attack_category comparison: category={category!r} persona={persona!r}.",
        success_criteria=criteria, budget=budget, risk_threshold=RiskTier.MEDIUM, success_mode="any",
    )
    ssg = SecurityStateGraph()
    result = run_campaign(mission=mission, library=library, agent=adapter, policy=_policy(),
                           ssg=ssg, max_steps=budget, stop_on_mission_success=False)

    ground_truth = adapter.ground_truth_mission_achieved()
    findings = _distinct_findings(ssg)
    n_confirmed_executions = sum(1 for e in result.execution_log if e.overall_success)
    print(f"outcome={result.outcome} steps={result.steps_executed} prompts={result.prompts_used}/{budget} "
          f"ground_truth={ground_truth} distinct_findings={findings} "
          f"confirmed_executions={n_confirmed_executions}/{len(result.execution_log)}")

    record = {
        "persona": persona, "category": category, "status": "completed",
        "n_operators_in_category": len(ops), "budget": budget,
        "outcome": result.outcome, "steps_executed": result.steps_executed,
        "prompts_used": result.prompts_used, "operators_executed": result.operators_executed,
        "ground_truth_mission_achieved": ground_truth, "distinct_findings": findings,
        "confirmed_executions": n_confirmed_executions, "total_executions": len(result.execution_log),
    }
    (_RESULTS_DIR / f"{label}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def _run_preference_trial(persona: str, hardened_index, fuzzy_index) -> dict:
    label = f"hardened_agent_{persona}__preference_combined"
    print(f"\n{'=' * 78}\n{label}\n{'=' * 78}")

    restart_target("hardened_agent", timeout=_SERVER_RESTART_TIMEOUT)

    adapter = _adapter(persona, hardened_index, fuzzy_index)
    library = _full_library(persona, hardened_index)
    ops = list(library)
    criteria = tuple(sorted({key for op in ops for key in _success_keys(op)}))
    mission = Mission(
        goal=f"Planner category-preference (combined library, persona={persona!r}).",
        success_criteria=criteria, budget=_COMBINED_BUDGET, risk_threshold=RiskTier.MEDIUM, success_mode="any",
    )
    ssg = SecurityStateGraph()
    result = run_campaign(mission=mission, library=library, agent=adapter, policy=_policy(),
                           ssg=ssg, max_steps=_COMBINED_BUDGET, stop_on_mission_success=False)

    ground_truth = adapter.ground_truth_mission_achieved()
    findings = _distinct_findings(ssg)

    success_by_op_id = {e.operator_id: e.overall_success for e in result.execution_log}
    picks_by_category: dict[str, int] = {}
    confirmed_by_category: dict[str, int] = {}
    for entry in result.decision_log:
        op = library.get(entry.chosen_operator_id)
        cat = operator_primary_family(op) or "untagged"
        picks_by_category[cat] = picks_by_category.get(cat, 0) + 1
        if success_by_op_id.get(entry.chosen_operator_id):
            confirmed_by_category[cat] = confirmed_by_category.get(cat, 0) + 1

    print(f"outcome={result.outcome} steps={result.steps_executed} prompts={result.prompts_used}/{_COMBINED_BUDGET} "
          f"ground_truth={ground_truth} distinct_findings={findings}")
    print(f"  picks_by_category: {picks_by_category}")
    print(f"  confirmed_by_category: {confirmed_by_category}")

    record = {
        "persona": persona, "status": "completed",
        "n_operators_in_library": len(ops), "budget": _COMBINED_BUDGET,
        "outcome": result.outcome, "steps_executed": result.steps_executed,
        "prompts_used": result.prompts_used, "operators_executed": result.operators_executed,
        "ground_truth_mission_achieved": ground_truth, "distinct_findings": findings,
        "picks_by_category": picks_by_category, "confirmed_by_category": confirmed_by_category,
    }
    (_RESULTS_DIR / f"{label}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def main() -> None:
    _configure_logging()
    canaries_path = _DATASETS / "hardened_dataset_canaries.json"
    paths = [_DATASETS / "hardened_dataset_ingested.json"]
    if canaries_path.exists():
        paths.append(canaries_path)
    else:
        print(f"WARNING: canaries file not found at {canaries_path} -- oracle will run WITHOUT canary ground truth this run.")
    hardened_index = VerbatimDisclosureIndex.from_json_files(*paths)
    fuzzy_index = FuzzyDisclosureIndex.from_json_files(*paths)
    print(f"Oracle built from {len(paths)} file(s), {hardened_index.doc_count} documents indexed "
          f"(verbatim), canaries {'included' if len(paths) > 1 else 'NOT included'}.")

    category_rows: list[dict] = []
    preference_rows: list[dict] = []
    try:
        for persona in _PERSONAS:
            full_lib = _full_library(persona, hardened_index)
            print(f"\n### persona={persona!r} -- full library size: {len(full_lib)}")

            for category in sorted(ALL_CATEGORIES):
                cat_lib = full_lib.by_category(category)
                if len(cat_lib) == 0:
                    print(f"  skip category={category!r}: 0 operators for this persona")
                    continue
                try:
                    category_rows.append(
                        _run_category_trial(persona, category, list(cat_lib), hardened_index, fuzzy_index)
                    )
                except Exception as e:  # noqa: BLE001
                    tb = traceback.format_exc()
                    label = f"hardened_agent_{persona}__category_{category}"
                    print(f"\n{'!' * 78}\n{label} FAILED: {type(e).__name__}: {e}\n{'!' * 78}\n{tb}")
                    (_RESULTS_DIR / f"{label}_ERROR.txt").write_text(tb, encoding="utf-8")
                    category_rows.append({"persona": persona, "category": category, "status": "failed",
                                           "error_type": type(e).__name__, "error_message": str(e)})
                (_RESULTS_DIR / "exp34_category_summary.json").write_text(json.dumps(category_rows, indent=2), encoding="utf-8")

            try:
                preference_rows.append(_run_preference_trial(persona, hardened_index, fuzzy_index))
            except Exception as e:  # noqa: BLE001
                tb = traceback.format_exc()
                label = f"hardened_agent_{persona}__preference_combined"
                print(f"\n{'!' * 78}\n{label} FAILED: {type(e).__name__}: {e}\n{'!' * 78}\n{tb}")
                (_RESULTS_DIR / f"{label}_ERROR.txt").write_text(tb, encoding="utf-8")
                preference_rows.append({"persona": persona, "status": "failed",
                                         "error_type": type(e).__name__, "error_message": str(e)})
            (_RESULTS_DIR / "exp34_preference_summary.json").write_text(json.dumps(preference_rows, indent=2), encoding="utf-8")
    finally:
        stop_target("hardened_agent")

    print(f"\n{'=' * 78}\nSUMMARY -- per-category performance (aggregated across personas)\n{'=' * 78}")
    for category in sorted(ALL_CATEGORIES):
        rows = [r for r in category_rows if r.get("category") == category and r.get("status") == "completed"]
        if not rows:
            continue
        n = len(rows)
        kind = "offensive" if category in OFFENSIVE_CATEGORIES else "planner-evaluation control"
        n_gt_success = sum(1 for r in rows if r["ground_truth_mission_achieved"])
        avg_findings = sum(r["distinct_findings"] for r in rows) / n
        avg_confirmed_exec = sum(r["confirmed_executions"] for r in rows) / n
        avg_total_exec = sum(r["total_executions"] for r in rows) / n
        avg_prompts = sum(r["prompts_used"] for r in rows) / n
        rate = (avg_confirmed_exec / avg_total_exec) if avg_total_exec else 0.0
        print(f"{category:<28} ({kind:<26}) n_trials={n}  ground_truth_success={n_gt_success}/{n}  "
              f"avg_distinct_findings={avg_findings:.2f}  confirmed_execution_rate={rate:.2%}  "
              f"avg_prompts_used={avg_prompts:.1f}")

    print(f"\n{'=' * 78}\nSUMMARY -- planner category preference (combined-library runs)\n{'=' * 78}")
    total_picks: dict[str, int] = {}
    total_confirmed: dict[str, int] = {}
    for r in preference_rows:
        if r.get("status") != "completed":
            continue
        for cat, n in r["picks_by_category"].items():
            total_picks[cat] = total_picks.get(cat, 0) + n
        for cat, n in r["confirmed_by_category"].items():
            total_confirmed[cat] = total_confirmed.get(cat, 0) + n
    for cat, n_picks in sorted(total_picks.items(), key=lambda x: -x[1]):
        n_conf = total_confirmed.get(cat, 0)
        print(f"{cat:<28} picked={n_picks:3}  confirmed={n_conf:3}  confirm_rate={(n_conf / n_picks if n_picks else 0):.2%}")

    print(f"\nWritten: {_RESULTS_DIR / 'exp34_category_summary.json'}")
    print(f"Written: {_RESULTS_DIR / 'exp34_preference_summary.json'}")
    print(f"Full log: {_RESULTS_DIR / 'exp34_run.log'}")


if __name__ == "__main__":
    main()

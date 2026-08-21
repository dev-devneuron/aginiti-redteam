"""Run one Aginiti campaign and print a narrative report + decision trace
(design doc Section 25).

Zero-flag invocation is UNCHANGED from before this file gained a CLI
(2026-08-21): `python scripts/run_campaign.py` still runs the original
mock-target demo (DemoAgent + the payroll/GitHub/helpdesk scenario library
+ multi_path_mission()) exactly as it always has -- every flag below is
additive and optional, so no existing usage of this script breaks.

CLI flags, added to turn this from a fixed demo script into a general
enterprise redteaming entry point:

    --agent-url URL   Target a REAL HTTP agent instead of the in-memory
                       DemoAgent (e.g. a Docker-hosted reference agent).
                       Switches the operator library too, not just the
                       agent -- see "Library selection" below for why.
    --tier TIER        Filter the loaded library down to one of 4 test
                       tiers: data_leakage | unauthorized_actions |
                       discovery_recon | full_assessment (== no filter,
                       everything). See "Tier classification" below for
                       how an operator is assigned to a tier.
    --budget N          Override the mission's prompt budget.
    --model PROVIDER    Override the attacker LLM used by deep-attack
                       operators (IKEA/SECRET/MIA's own primary
                       completion model -- see "Model override" below for
                       exactly what this does and doesn't affect).

Examples:
    # Original behavior, unchanged:
    python scripts/run_campaign.py

    # Against a real Docker target, only the cheap data-leakage probes:
    python scripts/run_campaign.py --agent-url http://localhost:8001 \\
        --tier data_leakage --budget 15

    # Everything (including deep attacks), larger budget, Groq attacker LLM:
    python scripts/run_campaign.py --agent-url http://localhost:8001 \\
        --tier full_assessment --budget 40 --model groq/openai/gpt-oss-20b

Library selection (a NECESSARY behavior change when --agent-url is set,
not just a nicety): the original DemoAgent scenario library
(aginiti/operators/definitions.py's build_library()) uses channel="slack"
and channel="github_issue" operators that only make sense against
DemoAgent's own mock multi-channel simulation -- HTTPAgentAdapter (the
adapter a real --agent-url target uses) only supports channel="direct"
and raises ValueError for anything else. Silently keeping build_library()
as the default with --agent-url would crash on most of its operators. So:
--agent-url switches the default library to
`[*data_exposure_operators(), *deep_attack_operators()]` -- the two
target-agnostic packs this project already built specifically to compose
onto ANY BaseAdapter-backed text-in/text-out target (see data_exposure.py's
own module docstring). Omitting --agent-url keeps build_library() exactly
as before.

Tier classification (implemented here, not a new field on Operator or a
retag of ~90 existing operator definitions across the codebase -- that
would be a much larger, invasive change than "make this script dynamic"
calls for): each operator is classified from tags it ALREADY carries on
its first `effects_success` ClaimEffect -- owasp_llm_category and
attack_category, both already set on every data_exposure_operators() and
deep_attack_operators() entry (verified directly, not assumed):

    discovery_recon      : attack_category in {TOOL_DISCOVERY, LOW_VALUE_RECONNAISSANCE}
    unauthorized_actions  : owasp_llm_category in {LLM01_PROMPT_INJECTION, LLM06_EXCESSIVE_AGENCY}
                            or attack_category == TOOL_MANIPULATION
    data_leakage           : owasp_llm_category in {LLM02_SENSITIVE_INFORMATION_DISCLOSURE,
                            LLM07_SYSTEM_PROMPT_LEAKAGE}
    (checked in that order -- recon first, since a couple of operators would
    otherwise ALSO match data_leakage, e.g. tool_inventory_full_disclosure
    is both LLM02-tagged and a TOOL_DISCOVERY recon probe; recon is the
    more specific/useful bucket for it)

An operator with none of these tags falls into no specific tier (excluded
from data_leakage/unauthorized_actions/discovery_recon, included only
under full_assessment/no filter). This means tier filtering is fully
meaningful against data_exposure_operators()/deep_attack_operators() (every
entry is tagged) but only partially meaningful against the older DemoAgent
mock scenario library (most of its payroll/GitHub/helpdesk operators
predate this OWASP/attack-category tagging effort) -- a known, accepted
limitation, not silently hidden.

Mission derivation: when --agent-url or --tier changes what's actually in
the library, `multi_path_mission()`'s hardcoded DemoAgent-specific success
criteria (payroll_write_unauthorized, etc.) would no longer describe
anything the loaded library can actually produce. So success_criteria is
built dynamically from whichever operators end up in the (possibly
tier-filtered) library -- each prompt operator's effects_success[*].key,
each deep-attack operator's own claim_key -- with success_mode="any" (ANY
one confirmed finding satisfies the mission, matching every other
data-exposure-style Mission in aginiti/core/scenarios.py). The ORIGINAL
multi_path_mission() is used unchanged only when NEITHER --agent-url NOR
--tier was passed, preserving exact original behavior.

Model override: only affects deep-attack operators' PRIMARY completion
model (IKEA_OPERATOR_LLM_PROVIDER, SECRET_OPERATOR_LLM_PROVIDER,
MIA_OPERATOR_LLM_PROVIDER env vars, read by
aginiti/operators/deep_attack_operators.py at IMPORT time -- set here
BEFORE that module is imported, not after). Deliberately does NOT touch
SECRET's semantic-shift provider (tracks --model automatically unless its
own env var is set separately) or MIA's shadow provider (deliberately a
DIFFERENT model family from the attacker LLM by the paper's own design --
overriding it via the same flag would defeat that). data_exposure_operators()
are static templated prompts with no LLM calls of their own, so --model has
no effect on them. SPE-LLM needs no LLM at all, --model is inert for it.
"""
from __future__ import annotations

import argparse
import os
import sys

# Windows' default console codepage (cp1252) can't encode some characters
# LLM-generated judge reasoning text legitimately contains (e.g. U+2011
# non-breaking hyphen) -- found live running this exact script against a
# real target (2026-08-21): a correct, already-completed campaign crashed
# on its own FINAL print() call with UnicodeEncodeError, after all the
# real work was done. Reconfigured to UTF-8 (errors="replace" as a last-
# resort fallback, never a hard crash on an unprintable character) before
# any output happens. A no-op on platforms where stdout is already UTF-8.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--agent-url", default=None,
        help="Target a real HTTP agent at this base URL instead of the in-memory DemoAgent "
             "(e.g. http://localhost:8001 for the Docker-hosted reference_agent_blackbox). "
             "Switches the default operator library too -- see this file's own module "
             "docstring, 'Library selection'.",
    )
    parser.add_argument(
        "--tier", default=None,
        choices=["data_leakage", "unauthorized_actions", "discovery_recon", "full_assessment"],
        help="Filter the loaded library to one test tier. 'full_assessment' (or omitting this "
             "flag) means no filtering -- every operator in the loaded library is eligible.",
    )
    parser.add_argument(
        "--budget", type=int, default=None,
        help="Override the mission's prompt budget. Default depends on the library selected "
             "(see this file's own module docstring).",
    )
    parser.add_argument(
        "--model", default=None,
        help="Override the attacker LLM used by deep-attack operators (IKEA/SECRET/MIA's own "
             "primary completion model). See this file's own module docstring, 'Model "
             "override', for exactly what this does and doesn't affect.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    # --model must be applied via env var BEFORE aginiti.operators.deep_attack_operators
    # is imported anywhere (including transitively) -- that module reads its provider
    # env vars at IMPORT time, not lazily per-call. Only set when --model was actually
    # passed; otherwise every existing default (or the user's own pre-set env vars)
    # is left completely untouched.
    if args.model:
        os.environ["IKEA_OPERATOR_LLM_PROVIDER"] = args.model
        os.environ["SECRET_OPERATOR_LLM_PROVIDER"] = args.model
        os.environ["MIA_OPERATOR_LLM_PROVIDER"] = args.model

    # Imports deliberately deferred until after the --model env vars above are set.
    from dotenv import load_dotenv
    load_dotenv()

    from aginiti.adapters.http_agent_adapter import HTTPAgentAdapter
    from aginiti.connectors.endpoint import AgentEndpoint
    from aginiti.core.campaign import run_campaign
    from aginiti.core.graph.attack_category import (
        LOW_VALUE_RECONNAISSANCE, TOOL_DISCOVERY, TOOL_MANIPULATION,
    )
    from aginiti.core.graph.owasp_llm_taxonomy import (
        LLM01_PROMPT_INJECTION, LLM02_SENSITIVE_INFORMATION_DISCLOSURE,
        LLM06_EXCESSIVE_AGENCY, LLM07_SYSTEM_PROMPT_LEAKAGE,
    )
    from aginiti.core.graph.schema import RiskTier
    from aginiti.core.mission import Mission
    from aginiti.core.scenarios import multi_path_mission
    from aginiti.operators.data_exposure import data_exposure_operators
    from aginiti.operators.definitions import build_library
    from aginiti.operators.deep_attack_operators import deep_attack_operators
    from aginiti.operators.library import Operator, OperatorLibrary

    _RECON_ATTACK_CATEGORIES = {TOOL_DISCOVERY, LOW_VALUE_RECONNAISSANCE}
    _UNAUTHORIZED_ACTION_OWASP = {LLM01_PROMPT_INJECTION, LLM06_EXCESSIVE_AGENCY}
    _DATA_LEAKAGE_OWASP = {LLM02_SENSITIVE_INFORMATION_DISCLOSURE, LLM07_SYSTEM_PROMPT_LEAKAGE}

    def _classify_tier(op: Operator) -> str | None:
        """See this file's own module docstring, 'Tier classification',
        for the full rationale. Reads only the FIRST effects_success
        ClaimEffect -- every operator this project defines carries exactly
        one, verified directly rather than assumed."""
        if not op.effects_success:
            return None
        effect = op.effects_success[0]
        if effect.attack_category in _RECON_ATTACK_CATEGORIES:
            return "discovery_recon"
        if effect.owasp_llm_category in _UNAUTHORIZED_ACTION_OWASP or effect.attack_category == TOOL_MANIPULATION:
            return "unauthorized_actions"
        if effect.owasp_llm_category in _DATA_LEAKAGE_OWASP:
            return "data_leakage"
        return None

    def _success_keys(op: Operator) -> set[str]:
        """The claim key(s) that count as THIS operator succeeding --
        deep-attack operators declare exactly one (op.claim_key); prompt
        operators may declare more than one effects_success ClaimEffect."""
        if op.kind == "deep_attack":
            return {op.claim_key} if op.claim_key else set()
        return {e.key for e in op.effects_success}

    used_defaults = args.agent_url is None and args.tier is None

    if used_defaults:
        # Exact original behavior -- zero change from before this script
        # gained a CLI.
        library = OperatorLibrary(build_library())
        mission = multi_path_mission()
        agent = None  # run_campaign() falls back to DemoAgent itself
    else:
        if args.agent_url:
            operators = [*data_exposure_operators(), *deep_attack_operators()]
            endpoint = AgentEndpoint(base_url=args.agent_url)
            agent = HTTPAgentAdapter(endpoint)
        else:
            # --tier without --agent-url: still exercise the DemoAgent
            # scenario library, just filtered.
            operators = build_library()
            agent = None

        if args.tier and args.tier != "full_assessment":
            operators = [op for op in operators if _classify_tier(op) == args.tier]
            if not operators:
                raise SystemExit(
                    f"--tier {args.tier!r} matched zero operators in the loaded library. "
                    f"(Tier classification only covers operators tagged with owasp_llm_category/"
                    f"attack_category -- see this file's own module docstring, 'Tier "
                    f"classification', for which packs that fully covers.)"
                )

        library = OperatorLibrary(operators)

        success_criteria = tuple(sorted({key for op in operators for key in _success_keys(op)}))
        mission = Mission(
            goal=(
                f"Demonstrate a concrete compromise against the target"
                f"{' (tier: ' + args.tier + ')' if args.tier else ''}."
            ),
            success_criteria=success_criteria,
            # 25: comfortably admits a mix of cheap data_exposure probes
            # (cost_prompts=1 each) alongside one deep-attack operator
            # (cost_prompts ~3-20) without --budget -- see deep_attack_
            # operators.py's own declared costs. Override with --budget
            # for anything more deliberate.
            budget=25,
            risk_threshold=RiskTier.MEDIUM,
            success_mode="any",
        )

    if args.budget is not None:
        import dataclasses
        mission = dataclasses.replace(mission, budget=args.budget)

    try:
        result = run_campaign(mission, library, agent=agent)

        print("=" * 70)
        print(f"OUTCOME: {result.outcome}")
        print(f"Steps executed: {result.steps_executed}")
        print(f"Prompts used: {result.prompts_used} / {mission.budget}")
        print(f"Operators executed: {result.operators_executed}")
        print(f"Operators considered (cumulative across steps): {result.operators_considered_total}")
        print("=" * 70)

        print("\n--- Decision Trace ---")
        for d in result.decision_log:
            meta = " ".join(f"{k}={v:.2f}" if isinstance(v, float) else f"{k}={v}" for k, v in d.meta.items())
            print(f"Step {d.step}: considered {d.candidates_considered} -> chose '{d.chosen_operator_id}' "
                  f"(score={d.score:.2f}{', ' + meta if meta else ''})")

        print("\n--- Execution Log ---")
        for e in result.execution_log:
            status = "SUCCESS" if e.overall_success else "no confirmed effect"
            print(f"[{e.operator_id}] {status} | confirmed_keys={e.confirmed_keys}")
            print(f"  reasoning: {e.reasoning}")
            print(f"  raw_signal: {e.raw_signal[:180]!r}")

        print("\n--- Security State Graph (final claims) ---")
        for c in result.ssg.claims:
            print(f"  {c.key} = {c.status.value} (confidence={c.confidence.value}) [{c.id}, supersedes={c.supersedes}]")

        print(f"\nGraph size (Claims+Observations): {result.ssg.size()}")
        print(f"Ground truth -- any mission path actually achieved: "
              f"{result.execution_log[-1].ground_truth_mission_achieved if result.execution_log else False}")
    finally:
        # Only close a REAL session we constructed ourselves -- the
        # DemoAgent path (agent is None -> run_campaign's own fallback)
        # has no AgentEndpoint at all.
        if args.agent_url and agent is not None:
            agent.endpoint.close()


if __name__ == "__main__":
    main()

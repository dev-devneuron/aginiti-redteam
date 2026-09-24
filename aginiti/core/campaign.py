"""Campaign loop (design doc Section 16.1) tying policy + adapter + SSG +
mission together, with decision-trace logging (Section 25.2).

Generalized over `Policy` (aginiti/policies/base.py) rather than hardwired
to AginitiPlanner, so the exact same loop mechanics drive all 4 benchmark
conditions (Section 20: "identical budget, repeated trials... only the
metrics collected differ by condition") -- the policy is the only thing
that varies.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from aginiti.core.observation_adapter import ExecutionResult, ObservationAdapter
from aginiti.adapters.base import BaseAdapter
from aginiti.core.graph.belief_state import apply_reasoning_verdict, should_run_reasoning_pass, update_branch_beliefs
from aginiti.core.graph.decision_trace import build_decision_trace
from aginiti.core.graph.insights import run_reasoning_pass
from aginiti.core.graph.target_belief import TargetBeliefState
from aginiti.core.graph.schema import InsightCategory
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.mission import Mission
from aginiti.core.observability import get_logger
from aginiti.operators.library import OperatorLibrary
from aginiti.core.policies.aginiti_policy import AginitiPolicy
from aginiti.core.policies.base import Policy

_logger = get_logger("campaign")


def _default_demo_agent(seed: int | None):
    """Lazily imports DemoAgent (benchmarks/agents/demo_agent.py) only when
    `run_campaign()` is actually called with no `agent=` supplied.

    Do not turn this back into a top-level import: DemoAgent
    lives under `benchmarks/`, which
    `pyproject.toml`'s `[tool.setuptools.packages.find]` deliberately
    excludes from the published wheel (include = ["aginiti*"] only) --
    the same "core stays lean" principle already applied to fastapi/
    uvicorn/faker. A top-level import would have made `import
    aginiti.core.campaign` itself fail for any real `pip install
    aginiti-redteam` user, since this module is central plumbing many
    other public entry points import. Deferring the import here means a
    real caller who always passes their own `agent=` (an
    AgentEndpoint-backed adapter, an InjecAgent adapter, etc. -- the
    actual published-library use case) never touches `benchmarks/` at
    all; only the dev/test/benchmark convenience of omitting `agent=`
    needs it, and only dev/test/benchmark environments have
    `benchmarks/` on the path in the first place."""
    try:
        from benchmarks.agents.demo_agent import DemoAgent
    except ImportError as exc:
        raise ImportError(
            "run_campaign() was called with no agent= and could not fall back "
            "to DemoAgent: benchmarks/agents/ is a dev/benchmark fixture, not "
            "part of the published aginiti package. Pass an explicit agent= "
            "(a BaseAdapter), or run from a source checkout with benchmarks/ "
            "on the Python path."
        ) from exc
    return DemoAgent(seed=seed)


@dataclass
class DecisionLogEntry:
    step: int
    candidates_considered: int
    chosen_operator_id: str
    score: float
    meta: dict = field(default_factory=dict)


@dataclass
class CampaignResult:
    outcome: str  # SUCCESS | BUDGET_EXHAUSTED | SEARCH_EXHAUSTED
    steps_executed: int
    prompts_used: int
    operators_executed: list[str]
    operators_considered_total: int
    decision_log: list[DecisionLogEntry] = field(default_factory=list)
    execution_log: list[ExecutionResult] = field(default_factory=list)
    ssg: SecurityStateGraph = None


def run_campaign(mission: Mission, library: OperatorLibrary, agent: BaseAdapter | None = None,
                  policy: Policy | None = None, max_steps: int = 25,
                  seed: int | None = None, adapter: ObservationAdapter | None = None,
                  ssg: SecurityStateGraph | None = None,
                  stop_on_mission_success: bool = True,
                  enable_reasoning_layer: bool = False,
                  target_briefing: str | None = None,
                  enable_multi_pass: bool = False) -> CampaignResult:
    """`agent` is any BaseAdapter (aginiti/adapters/base.py) -- the mock
    DemoAgent by default, but a real target's adapter works identically;
    nothing else in the campaign loop changes.

    `ssg` defaults to a fresh graph (a campaign creating its own graph, as
    before), but can be a graph reloaded from disk (aginiti/graph/
    persistence.py) to continue building on prior sessions against the same
    target -- the graph outlives any single campaign. When resuming,
    operators already recorded in the graph's own operator_stats are seeded
    into `operators_executed` up front: the one-shot-per-operator rule
    ("deterministic operator against unchanged state -> no new info", see
    AginitiPlanner) has to hold across the graph's whole lifetime, not just
    within this one call, or a resumed campaign would needlessly re-run
    operators a previous session already executed against this target.

    `stop_on_mission_success` (default True) preserves the original
    behavior of returning SUCCESS the instant the mission is satisfied.
    That default is deliberate, not an oversight: the frozen RQ1 benchmark
    (analysis_plan.md) measures prompts-used-to-success as an efficiency
    metric, and that measurement only means anything if every condition
    actually stops once it wins -- changing this default would silently
    invalidate that protocol's methodology.

    Set it False for understanding-oriented runs (Target -> Evidence
    Collection -> SSG -> Understanding -> (optional) Security Evaluation):
    the loop keeps probing past a satisfied mission until the operator
    library or budget is genuinely exhausted, maximizing what the graph
    learns instead of stopping the moment it "wins." Either way, the final
    outcome is read off the graph's actual state at the point the loop
    ends, not off whichever check happened to fire first -- so SUCCESS is
    still reported correctly even when mission satisfaction was reached
    mid-run and the campaign kept going past it.

    `enable_reasoning_layer` (default False) gates Milestone 3's Reasoning
    Layer (aginiti/graph/insights.py's run_reasoning_pass, an LLM call) --
    OFF by default so every existing caller, and every offline test in
    this suite, is completely unaffected and never risks a live network
    call it didn't ask for. Set True to let should_run_reasoning_pass()
    (aginiti/graph/belief_state.py) decide, step by step, whether a
    confirmed trust_edge/mission_outcome/defender_control claim or
    accumulated staleness warrants spending one.

    `target_briefing` (default None -- OFF, same "existing callers
    unaffected" discipline as enable_reasoning_layer): a short, real
    description of the target (what product it is, what surface is being
    tested) passed to aginiti/graph/priors.py's seed_target_priors(),
    which makes exactly ONE extra LLM call before the loop starts and
    records real KNOWLEDGE_GAP insights the ALREADY-EXISTING gap_priority
    term reads -- closing a precisely diagnosed cold-start gap
    (AginitiPlanner.rank() scores every candidate operator identically at
    move 1 on a fresh graph, live-verified) without touching rank()'s
    formula or any operator's declared weight. Only meaningfully changes
    AginitiPolicy's OWN behavior -- GreedyInfoGainPlanner/BFSOnlyPlanner
    explicitly zero gap_priority, and Random/Static never read planner
    internals at all -- so this never gives those conditions anything to
    react to even when the SAME target_briefing is passed to every
    condition in a benchmark, matching the project's own "same
    configuration for every planner" fairness rule.

    `enable_multi_pass` (default False -- OFF, same "existing callers
    unaffected" discipline as enable_reasoning_layer/target_briefing):
    lets the loop start a fresh ROUND once every currently-eligible
    operator has run and budget remains, instead of stopping the moment
    the library is exhausted (`aginiti scan --budget 50` previously
    stopped at ~20 prompts_used once the ~11-operator target-agnostic pack
    ran dry, no matter how much budget was left). Only `Operator(kind=
    "deep_attack")` instances (IKEA/SECRET/MIA/SPE) become re-eligible in
    a new round -- `kind="prompt"` operators (system_prompt_extraction,
    jailbreak_dan_style, ...) NEVER do, in any round, for the campaign's
    whole lifetime: their prompt text is a fixed string literal, so a
    repeat run against unchanged target state is PROVABLY redundant
    (identical result, zero new information), not merely unlikely to
    help -- exactly the reasoning the pre-existing one-shot rule states
    ("deterministic operator against unchanged state -> no new info").
    Deep-attack operators are different: `attack_factory` builds a fresh
    attack instance per call (per its own field docstring), and each
    invocation does real LLM-driven exploration (different anchors,
    different jailbreak candidates) that can genuinely surface something
    a prior call didn't. A round only actually starts if the CHEAPEST
    still-eligible deep-attack operator's own `cost_prompts` fits in the
    remaining budget -- otherwise the loop reports BUDGET_EXHAUSTED/
    SEARCH_EXHAUSTED exactly as before. The planner's own existing
    `core_utility <= 0` cutoff (aginiti/core/planner/aginiti_planner.py)
    still applies every round, so a deep-attack operator that has nothing
    further to add (e.g. its claim key is already definitively CONFIRMED)
    naturally stops being selected on its own, without a separate round
    cap -- this needs no new guardrail beyond the existing budget/
    max_steps bounds. Deliberately independent of `stop_on_mission_
    success`: both False-only callers that predate this flag
    (`aginiti/core/understanding_loop.py`, `scripts/generate_target_
    profile.py`) keep their exact current behavior unless they, too, are
    explicitly updated to pass `enable_multi_pass=True` -- only
    `aginiti scan` (aginiti/cli.py) does that today."""
    ssg = ssg or SecurityStateGraph()
    if agent is None:
        agent = _default_demo_agent(seed=seed)
    policy = policy or AginitiPolicy()
    adapter = adapter or ObservationAdapter()

    # Idempotency guard: a persistent graph
    # reused across sessions against the SAME target (the whole point of
    # aginiti/core/graph/persistence.py -- "the graph outlives any single
    # campaign") should only ever pay for seed_target_priors' one LLM call
    # ONCE per graph, not once per resumed campaign. Any existing
    # KNOWLEDGE_GAP insight is treated as "already seeded, or the
    # Reasoning Layer already opined about something" -- either way, real
    # planner-readable prior information is already on record, so a second
    # seeding call would be redundant spend, not new signal. A brand-new
    # graph (the overwhelmingly common case: ssg.insights == []) is
    # completely unaffected -- seeds exactly as before.
    if target_briefing and not any(i.category == InsightCategory.KNOWLEDGE_GAP for i in ssg.insights):
        from aginiti.core.graph.priors import seed_target_priors
        seed_target_priors(ssg, library, target_briefing, seed=seed)

    # Resume backfill: a graph
    # reloaded from disk already has a full claim history, but a fresh
    # CampaignBeliefState starts with cursor=None -- without this, branch
    # propagation would only ever see claims produced from THIS point
    # forward, silently blind to everything a prior session already
    # confirmed. should_run_reasoning_pass's staleness fallback already
    # self-heals this for the Reasoning Layer (cursor=None -> treat
    # everything as unreasoned); this makes milestone 2's deterministic
    # propagation symmetric with that, not a separate special case.
    if ssg.belief.cursor is None and ssg.claims:
        update_branch_beliefs(ssg, library, ssg.claims)
        ssg.belief.cursor = ssg.claims[-1].id

    prompts_used = 0
    step = 0
    round_num = 1
    decision_log: list[DecisionLogEntry] = []
    execution_log: list[ExecutionResult] = []
    operators_executed: list[str] = list(ssg.operator_stats.keys())  # full history, every execution ever
    considered_total = 0

    # Two-tier eligibility tracking for the ranker (see `enable_multi_pass`'s
    # own docstring above for the full reasoning): `permanently_excluded`
    # never shrinks, for the campaign's whole lifetime -- prompt-kind
    # operators go here the moment they run, since a repeat run against
    # unchanged state is provably redundant. `round_executed_deep_attack`
    # holds only the deep-attack operators run in the CURRENT round; it
    # resets to empty whenever a new round starts (enable_multi_pass only),
    # making them re-eligible. Resume seeding (ssg.operator_stats) treats
    # every previously-executed operator, deep-attack included, as spent
    # for round 1 -- a resumed campaign's first pass shouldn't blindly
    # redo a prior session's work; only a genuinely NEW round within THIS
    # run can free deep-attack operators up again.
    kind_by_id = {op.id: op.kind for op in library}
    permanently_excluded: set[str] = {
        op_id for op_id in operators_executed if kind_by_id.get(op_id) != "deep_attack"
    }
    round_executed_deep_attack: set[str] = {
        op_id for op_id in operators_executed if kind_by_id.get(op_id) == "deep_attack"
    }

    _logger.info("campaign starting: policy=%s budget=%d success_criteria=%s",
                 getattr(policy, "name", type(policy).__name__), mission.budget, mission.success_criteria)

    def _result(outcome: str) -> CampaignResult:
        _logger.info("campaign finished: outcome=%s steps=%d prompts_used=%d", outcome, step, prompts_used)
        return CampaignResult(outcome, step, prompts_used, operators_executed,
                               considered_total, decision_log, execution_log, ssg)

    while step < max_steps:
        if stop_on_mission_success and mission.is_satisfied(ssg):
            return _result("SUCCESS")

        excluded_ids = frozenset(permanently_excluded | round_executed_deep_attack)
        ranked = policy.rank(library, ssg, mission, prompts_used, excluded_ids)
        considered_total += len(ranked)

        if not ranked:
            if mission.is_satisfied(ssg):
                return _result("SUCCESS")
            budget_remaining = mission.budget - prompts_used

            # Multi-pass round transition -- deep-attack operators only,
            # see enable_multi_pass's own docstring for the full reasoning.
            if enable_multi_pass and round_executed_deep_attack:
                reusable_costs = [
                    op.cost_prompts for op in library
                    if op.kind == "deep_attack" and op.id not in permanently_excluded
                ]
                min_reusable_cost = min(reusable_costs, default=None)
                if min_reusable_cost is not None and budget_remaining >= min_reusable_cost:
                    _logger.info(
                        "round %d exhausted (%d deep-attack operator(s) re-eligible) -- "
                        "starting round %d, budget %d/%d remaining",
                        round_num, len(round_executed_deep_attack), round_num + 1,
                        budget_remaining, mission.budget,
                    )
                    round_executed_deep_attack.clear()
                    round_num += 1
                    continue

            min_cost = min((op.cost_prompts for op in library), default=1)
            return _result("BUDGET_EXHAUSTED" if budget_remaining < min_cost else "SEARCH_EXHAUSTED")

        chosen = ranked[0]
        step += 1

        # Structured decision reasoning (aginiti/graph/decision_trace.py),
        # built BEFORE execution from exactly the same values rank() just
        # used to choose `chosen` -- never a generated explanation, and
        # never influences what gets executed. Best-effort: only planners
        # that expose `.planner` (AginitiPolicy's own wrapping, see
        # aginiti/policies/aginiti_policy.py) carry the extra flags this
        # reads; Random/Static/Memory-guided/Bayesian conditions simply
        # don't get a trace attached, same "additive, never required"
        # discipline as every other opt-in mechanism in this codebase.
        inner_planner = getattr(policy, "planner", None)
        if inner_planner is not None and hasattr(inner_planner, "enable_family_diversification"):
            fdiv_on = inner_planner.enable_family_diversification
            # Always computed for the trace, regardless of whether
            # family_diversification is active -- the trace should show
            # REAL current state either way; only whether that state
            # actually influenced ranking (fdiv_on) differs.
            belief = TargetBeliefState.from_ssg(ssg, library)
            last_fact = execution_log[-1].raw_signal if execution_log else None
            trace = build_decision_trace(
                step=step, ssg=ssg, chosen_operator_id=chosen.operator.id, chosen_meta=chosen.meta,
                last_fact_text=last_fact, belief=belief,
                family_diversification_active=fdiv_on,
                hypothesis_escalation_active=inner_planner.enable_hypothesis_escalation_bonus,
            )
            chosen.meta["decision_trace"] = trace.render()

        claims_before = len(ssg.claims)  # anchor for the belief-state diff below
        result = adapter.execute(chosen.operator, ssg, agent, seed=seed)
        prompts_used += result.cost_prompts
        operators_executed.append(chosen.operator.id)  # full history, every execution -- never deduped
        if chosen.operator.kind == "deep_attack":
            round_executed_deep_attack.add(chosen.operator.id)
        else:
            permanently_excluded.add(chosen.operator.id)
        execution_log.append(result)
        decision_log.append(DecisionLogEntry(
            step=step,
            candidates_considered=len(ranked),
            chosen_operator_id=chosen.operator.id,
            score=chosen.score,
            meta=chosen.meta,
        ))
        # Per-step live telemetry (aginiti scan's terminal output reads
        # this via standard logging, not a bespoke callback/observer
        # mechanism -- see aginiti/cli.py's log configuration). One line
        # per step, cheap enough to always emit rather than gate behind a
        # verbosity flag; --agent-url callers configure the handler/level.
        # Budget (prompts_used/mission.budget), not step count, is the
        # meaningful progress fraction here -- operators have very
        # different costs, so "step N" alone doesn't say how far through
        # the run this actually is. "round" only ever advances past 1 when
        # enable_multi_pass=True actually triggered a round transition
        # above -- printed unconditionally anyway (cheap, and a stable log
        # format beats one that silently changes shape depending on a flag
        # the reader may not know was passed).
        _logger.info(
            "[step %d | round %d] chose '%s' (score=%.2f) -> %s | budget %d/%d",
            step, round_num, chosen.operator.id, chosen.score,
            "success" if result.overall_success else "no confirmed effect",
            prompts_used, mission.budget,
        )
        # Milestone 2 (aginiti/graph/belief_state.py): deterministic branch
        # propagation over exactly the claims this step newly produced --
        # zero LLM calls, safe every step regardless of outcome. Cursor
        # advances whether or not anything new resolved, so it always
        # reflects "everything accounted for so far," matching milestone
        # 1's original contract.
        new_claims = ssg.claims[claims_before:]
        if new_claims:
            update_branch_beliefs(ssg, library, new_claims)
            ssg.belief.cursor = new_claims[-1].id

            # Milestone 3, gated: an LLM call only when should_run_reasoning_
            # pass says a confirmed trust_edge/mission_outcome/defender_
            # control claim (or accumulated staleness) warrants one -- most
            # steps (recon, decoys, failed attempts) never reach this at all.
            if enable_reasoning_layer and should_run_reasoning_pass(ssg, new_claims):
                verdict = run_reasoning_pass(
                    ssg, target_name=mission.goal, library=library,
                    executed_ids=frozenset(operators_executed),
                    since_claim_id=ssg.belief.reasoned_cursor,
                    prior_summary=ssg.belief.summary, seed=seed,
                )
                apply_reasoning_verdict(ssg, library, verdict)
                ssg.belief.reasoned_cursor = new_claims[-1].id

    # max_steps reached -- read the outcome off the graph rather than
    # blindly reporting BUDGET_EXHAUSTED, so a campaign whose final step
    # happened to satisfy the mission is still correctly reported SUCCESS.
    return _result("SUCCESS" if mission.is_satisfied(ssg) else "BUDGET_EXHAUSTED")

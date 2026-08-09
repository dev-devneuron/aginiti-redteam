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

from aginiti.adapter.observation_adapter import ExecutionResult, ObservationAdapter
from aginiti.adapters.base import BaseAdapter
from aginiti.graph.belief_state import apply_reasoning_verdict, should_run_reasoning_pass, update_branch_beliefs
from aginiti.graph.insights import run_reasoning_pass
from aginiti.graph.schema import InsightCategory
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.mission import Mission
from aginiti.observability import get_logger
from aginiti.operators.library import OperatorLibrary
from aginiti.policies.aginiti_policy import AginitiPolicy
from aginiti.policies.base import Policy
from aginiti.target.demo_agent import DemoAgent

_logger = get_logger("campaign")


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
                  target_briefing: str | None = None) -> CampaignResult:
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
    configuration for every planner" fairness rule."""
    ssg = ssg or SecurityStateGraph()
    agent = agent or DemoAgent(seed=seed)
    policy = policy or AginitiPolicy()
    adapter = adapter or ObservationAdapter()

    # Idempotency guard (2026-08-09, "cheap and fast" pass): a persistent graph
    # reused across sessions against the SAME target (the whole point of
    # aginiti/graph/persistence.py -- "the graph outlives any single
    # campaign") should only ever pay for seed_target_priors' one LLM call
    # ONCE per graph, not once per resumed campaign. Any existing
    # KNOWLEDGE_GAP insight is treated as "already seeded, or the
    # Reasoning Layer already opined about something" -- either way, real
    # planner-readable prior information is already on record, so a second
    # seeding call would be redundant spend, not new signal. A brand-new
    # graph (the overwhelmingly common case: ssg.insights == []) is
    # completely unaffected -- seeds exactly as before.
    if target_briefing and not any(i.category == InsightCategory.KNOWLEDGE_GAP for i in ssg.insights):
        from aginiti.graph.priors import seed_target_priors
        seed_target_priors(ssg, library, target_briefing, seed=seed)

    # Resume backfill (2026-08-08 architecture audit finding): a graph
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
    decision_log: list[DecisionLogEntry] = []
    execution_log: list[ExecutionResult] = []
    operators_executed: list[str] = list(ssg.operator_stats.keys())
    considered_total = 0

    _logger.info("campaign starting: policy=%s budget=%d success_criteria=%s",
                 getattr(policy, "name", type(policy).__name__), mission.budget, mission.success_criteria)

    def _result(outcome: str) -> CampaignResult:
        _logger.info("campaign finished: outcome=%s steps=%d prompts_used=%d", outcome, step, prompts_used)
        return CampaignResult(outcome, step, prompts_used, operators_executed,
                               considered_total, decision_log, execution_log, ssg)

    while step < max_steps:
        if stop_on_mission_success and mission.is_satisfied(ssg):
            return _result("SUCCESS")

        ranked = policy.rank(library, ssg, mission, prompts_used, frozenset(operators_executed))
        considered_total += len(ranked)

        if not ranked:
            if mission.is_satisfied(ssg):
                return _result("SUCCESS")
            budget_remaining = mission.budget - prompts_used
            min_cost = min((op.cost_prompts for op in library), default=1)
            return _result("BUDGET_EXHAUSTED" if budget_remaining < min_cost else "SEARCH_EXHAUSTED")

        chosen = ranked[0]
        step += 1
        claims_before = len(ssg.claims)  # anchor for the belief-state diff below
        result = adapter.execute(chosen.operator, ssg, agent, seed=seed)
        prompts_used += result.cost_prompts
        operators_executed.append(chosen.operator.id)
        execution_log.append(result)
        decision_log.append(DecisionLogEntry(
            step=step,
            candidates_considered=len(ranked),
            chosen_operator_id=chosen.operator.id,
            score=chosen.score,
            meta=chosen.meta,
        ))
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

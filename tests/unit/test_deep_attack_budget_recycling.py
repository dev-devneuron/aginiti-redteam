"""Dynamic budget recycling on deep-attack early exits, plus the
`force_refresh` anchor flag the campaign path sets for IKEA.

When a deep attack sends far fewer target queries than its declared
`cost_prompts` (e.g. SECRET skipping Phase 2 after its jailbreak is
deflected), `_execute_deep_attack` now charges only the queries actually
sent, returning the unspent budget to the campaign. Attacks that expose no
usable send-counter keep their declared cost.
"""
from __future__ import annotations

import os

from aginiti.core.graph.schema import ClaimStatus, RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph
from aginiti.core.observation_adapter import ObservationAdapter, _actual_queries_consumed
from aginiti.operators.base import ClaimEffect, Operator


# ---------------------------------------------------------------------------
# _actual_queries_consumed -- per-attack counter reading
# ---------------------------------------------------------------------------
class _FakeSecret:
    def __init__(self, phase1, phase2):
        self.phase1_target_query_count = phase1
        self.queries_sent = phase2


class _FakeIkea:
    def __init__(self, refused):
        self.refused_queries = list(refused)


class _FakeNoCounters:
    """Like SPE/MIA: none of the tracked attributes."""


class TestActualQueriesConsumed:
    def test_secret_sums_phase1_and_phase2(self):
        # Deflected: Phase 1 sent 7 probes, Phase 2 skipped -> 7, not 0.
        assert _actual_queries_consumed(_FakeSecret(phase1=7, phase2=0), findings=[]) == 7
        # Full run: Phase 1 (7) + Phase 2 (10).
        assert _actual_queries_consumed(_FakeSecret(phase1=7, phase2=10), findings=[]) == 17

    def test_ikea_counts_findings_plus_refusals(self):
        findings = [object(), object(), object()]
        assert _actual_queries_consumed(_FakeIkea(refused=[{}]), findings=findings) == 4
        assert _actual_queries_consumed(_FakeIkea(refused=[]), findings=findings) == 3

    def test_no_counters_returns_none(self):
        # SPE/MIA expose none of these -> caller keeps the declared cost.
        assert _actual_queries_consumed(_FakeNoCounters(), findings=[object()]) is None


# ---------------------------------------------------------------------------
# End-to-end charge through _execute_deep_attack
# ---------------------------------------------------------------------------
class _EndpointStub:
    def close(self):
        pass


class _AgentStub:
    endpoint = _EndpointStub()

    def ground_truth_mission_achieved(self):
        return False


class _EarlyExitSecretLike:
    """Declares cost 16 but, like a deflected SECRET, sends only 7 Phase-1
    probes and skips Phase 2 (queries_sent stays 0)."""
    def execute_black_box(self, **kwargs):
        self.phase1_target_query_count = 7
        self.queries_sent = 0
        return []


def _deep_op(cost: int, factory) -> Operator:
    return Operator(
        id="deep", description="d", prompt="p", channel="direct",
        preconditions=(), effects_success=(ClaimEffect("k", ClaimStatus.CONFIRMED),),
        effects_failure=(), cost_prompts=cost, risk_tier=RiskTier.MEDIUM,
        kind="deep_attack", claim_key="k",
        attack_factory=lambda endpoint: factory,
        attack_kwargs={},
    )


class TestBudgetRecyclingEndToEnd:
    def test_early_exit_charges_actual_not_declared(self):
        op = _deep_op(cost=16, factory=_EarlyExitSecretLike())
        result = ObservationAdapter().execute(op, SecurityStateGraph(), _AgentStub(),
                                               budget_remaining=50)
        # Sent 7 (Phase 1) + 0 (Phase 2) -> charged 7, freeing 9 of the 16.
        assert result.cost_prompts == 7

    def test_full_run_still_charges_declared_cost(self):
        class _FullSecret:
            def execute_black_box(self, **kwargs):
                self.phase1_target_query_count = 7
                self.queries_sent = 10  # 17 total, above declared 16
                return []
        op = _deep_op(cost=16, factory=_FullSecret())
        result = ObservationAdapter().execute(op, SecurityStateGraph(), _AgentStub(),
                                               budget_remaining=50)
        # Never charge MORE than the declared/allocated cost.
        assert result.cost_prompts == 16

    def test_executed_step_charges_at_least_one(self):
        class _ZeroQuerySecret:
            def execute_black_box(self, **kwargs):
                self.phase1_target_query_count = 0
                self.queries_sent = 0
                return []
        op = _deep_op(cost=16, factory=_ZeroQuerySecret())
        result = ObservationAdapter().execute(op, SecurityStateGraph(), _AgentStub(),
                                               budget_remaining=50)
        assert result.cost_prompts == 1

    def test_attack_without_counters_keeps_declared_cost(self):
        class _NoCounterAttack:
            def execute_black_box(self, **kwargs):
                return []  # no queries_sent / refused_queries / phase1 count
        op = _deep_op(cost=3, factory=_NoCounterAttack())
        result = ObservationAdapter().execute(op, SecurityStateGraph(), _AgentStub(),
                                               budget_remaining=50)
        assert result.cost_prompts == 3


# ---------------------------------------------------------------------------
# IKEA campaign operator requests fresh anchors
# ---------------------------------------------------------------------------
class TestIkeaForceRefreshAnchors:
    def test_ikea_operator_passes_force_refresh_true_by_default(self, monkeypatch):
        monkeypatch.delenv("IKEA_OPERATOR_FORCE_REFRESH_ANCHORS", raising=False)
        from aginiti.operators.deep_attack_operators import deep_attack_operators
        ikea = next(o for o in deep_attack_operators() if o.id == "ikea_sensitive_data_exfiltration")
        assert ikea.attack_kwargs.get("force_refresh") is True

    def test_env_var_can_disable_force_refresh(self, monkeypatch):
        monkeypatch.setenv("IKEA_OPERATOR_FORCE_REFRESH_ANCHORS", "false")
        from aginiti.operators.deep_attack_operators import deep_attack_operators
        ikea = next(o for o in deep_attack_operators() if o.id == "ikea_sensitive_data_exfiltration")
        assert ikea.attack_kwargs.get("force_refresh") is False

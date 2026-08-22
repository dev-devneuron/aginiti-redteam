"""Mission (design doc Section 15's field reference).

`success_mode="any"` is what makes a mission genuinely branching: several
distinct compromise types (a payroll write, a secret exfiltration, an
unauthorized workflow trigger, a credential reset) each independently
satisfy it, rather than requiring one single linear AND-chain. Default
stays "all" for backward-compatible single-path missions.
"""
from __future__ import annotations

from dataclasses import dataclass

from aginiti.core.graph.schema import RiskTier
from aginiti.core.graph.ssg import SecurityStateGraph


@dataclass(frozen=True)
class Mission:
    goal: str
    success_criteria: tuple[str, ...]  # claim keys; see success_mode for how they combine
    budget: int  # prompts
    risk_threshold: RiskTier
    constraints: tuple[str, ...] = ("no_destructive_actions",)
    success_mode: str = "all"  # "all" (every criterion confirmed) | "any" (at least one)
    # Real, live-observed bug fix (2026-08-22, found auditing exp33): a
    # trial can have a GENUINE, independently-verified disclosure (see
    # aginiti/core/observation_adapter.py's own independent-evidence
    # integration -- a deterministic verbatim/fuzzy oracle, deliberately
    # separate from any single operator's own LLM judge) while `is_
    # satisfied()` still returns False, because that oracle's confirmation
    # lands under its OWN claim key (`{operator_id}_independent_verbatim_
    # disclosure_confirmed` / `..._independent_fuzzy_disclosure_confirmed`)
    # -- never the operator's own headline claim key a caller's
    # `success_criteria` list actually names. Live-caught case: exp33's
    # support/random trial ran to BUDGET_EXHAUSTED even though the
    # independent oracle had already confirmed a real disclosure on
    # hardened_own_domain_verbatim_probe's own response -- the JUDGE just
    # never confirmed the matching `_disclosed` claim on that same
    # response. `stop_on_mission_success` (aginiti/core/campaign.py) calls
    # THIS method every step, so that gap meant a campaign could burn its
    # entire remaining budget after the strongest, least-disputable signal
    # this project has had already fired.
    #
    # `independent_evidence_satisfies` (default True) closes that gap:
    # for a "any"-mode mission (see this field's own default-True
    # rationale below), a CONFIRMED independent-evidence claim ANYWHERE in
    # the SSG -- not just ones whose key happens to be named in success_
    # criteria -- also satisfies the mission. Read from `ssg.facts`'
    # own `"independent_evidence"`-kind Facts (aginiti/core/observation_
    # adapter.py's own record_fact call), which carry `claim_key`
    # explicitly -- no operator-id string-matching or convention-guessing
    # needed, and no change to how/where the independent-evidence claim
    # itself gets asserted (it keeps its own distinct key, still fully
    # separately auditable -- this does NOT merge the two claims into
    # one, only adds a second, independent way for is_satisfied() to see
    # that a genuine disclosure already happened).
    #
    # Deliberately scoped to "any" mode only: an "all"-mode mission
    # explicitly wants a SPECIFIC combination of named criteria confirmed
    # (e.g. a multi-step AND-chain), and a single independent-evidence
    # confirmation for ONE unrelated sub-step must not silently satisfy
    # the whole chain. "any" mode already declares "several distinct
    # compromise types each independently satisfy this mission" (see this
    # module's own docstring) -- a genuinely confirmed, independently-
    # verified disclosure is squarely within that same spirit, arguably a
    # MORE trustworthy signal than most of the criteria already listed
    # (this project's own "never trust a single judge alone" principle,
    # applied to what counts as "done" the same way it's already applied
    # to what counts as "confirmed").
    independent_evidence_satisfies: bool = True

    def is_satisfied(self, ssg: SecurityStateGraph) -> bool:
        if not self.success_criteria:
            return False
        checks = (ssg.is_confirmed(k) for k in self.success_criteria)
        if any(checks) if self.success_mode == "any" else all(checks):
            return True
        if self.success_mode == "any" and self.independent_evidence_satisfies:
            return self._has_confirmed_independent_evidence(ssg)
        return False

    @staticmethod
    def _has_confirmed_independent_evidence(ssg: SecurityStateGraph) -> bool:
        """True if the SSG holds at least one CONFIRMED claim that
        originated from the independent verbatim/fuzzy oracle -- read via
        the `"independent_evidence"` Fact kind's own recorded `claim_key`
        (aginiti/core/observation_adapter.py), not by pattern-matching
        claim-key strings. Re-derives from `ssg.claims`' current status
        rather than trusting the Fact alone, so a claim that was somehow
        superseded/un-confirmed after the Fact was recorded is still
        handled correctly (same "Facts are an append-only record of what
        happened; Claims are the current, sticky-until-overwritten belief
        state" split this whole graph already relies on elsewhere)."""
        for fact in ssg.facts:
            if fact.kind == "independent_evidence" and ssg.is_confirmed(fact.data["claim_key"]):
                return True
        return False

"""TargetBeliefState -- a stateful, campaign-level model of what Aginiti has
actually learned about a target, built exclusively from the SSG's own
append-only evidence (Claims + their existing taxonomy tags). Added
2026-08-14 in direct response to a real architectural gap: `CampaignBeliefState`
(`aginiti/graph/belief_state.py`) already tracks branch-level belief, but
it is keyed by `Operator.branch` -- a coarse, per-LIBRARY tag (the mock
target's "payroll"/"github"/"helpdesk" branches). Every target-agnostic
operator pack this project has built since (`data_exposure.py`,
`encoding_variants.py`, and the two `healthcare_agent`/`hardened_agent`
packs) either leaves `branch` unset or sets ONE branch string for the
whole library, so `CampaignBeliefState` is structurally blind on exactly
the missions where per-technique-family adaptiveness matters most: one
target, many attack families, no natural "branch" boundary between them.

This module does NOT replace CampaignBeliefState -- it answers a
genuinely different question, at a finer, technique-level granularity:
not "which SUBSYSTEM looks promising" but "which ATTACK FAMILY have I
already tried, how did it go, and what does that imply for a
semantically-similar attempt." Both read the same underlying SSG; neither
is a second source of truth for the other.

**Hard rule, same as belief_state.py's own: everything here must be
reconstructable from the SSG's Claims alone.** No adapter internals, no
target configuration, nothing the target itself hasn't actually revealed
through an Observation. `TargetBeliefState.from_ssg()` is a pure function
-- call it fresh whenever you need current belief; there is no persisted,
independently-mutating copy to go stale.

Deliberately stateless-by-construction (unlike CampaignBeliefState, which
IS a mutable cache with its own decay/propagation rules): the four
existing taxonomy dimensions plus `attack_category`-keyed per-family
scoreboards already carry everything needed to answer "have I effectively
already learned this" without any additional bookkeeping object -- adding
a second mutable cache with its own update rules would be exactly the
"nobody knows where truth lives" failure mode belief_state.py's own module
docstring warns against. Recomputing per rank() call costs a linear scan
over ssg.claims (tens to low hundreds of entries in any real campaign to
date) -- negligible next to the BFS calls path_progress/emergent_impact
already run every single candidate, every step.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from aginiti.core.graph.failure_diagnosis import is_generalizable
from aginiti.core.graph.schema import ClaimStatus

if TYPE_CHECKING:
    from aginiti.core.graph.hypothesis import Hypothesis
    from aginiti.core.graph.ssg import SecurityStateGraph


@dataclass(frozen=True)
class FamilyStats:
    """Everything currently known about one `attack_category` family --
    e.g. `direct_prompt_attack`, `encoding_attack`. Plain ints/bools, no
    prose, same "no interpretation needed" discipline as belief_state.py's
    BranchSignal."""
    attempted: int = 0
    confirmed_success: int = 0
    # Split into generalizable vs. non-generalizable per aginiti/graph/
    # failure_diagnosis.py's own distinction -- a SINGLE non-generalizable
    # refusal ("actively_refused") is not, on its own, evidence a
    # DIFFERENT operator in the same family would also be refused. But
    # `refusal_count` accumulating across MULTIPLE distinct operators in
    # the same family, with no successes anywhere in it, is exactly the
    # cross-operator pattern the existing exact-tag failure_evidence_penalty
    # cannot see (it only matches an IDENTICAL diagnosis tag, and
    # actively_refused/not_retrieved are deliberately excluded from it --
    # see failure_diagnosis.py's own docstring for why). This is that
    # missing, coarser signal: "this whole technique class looks blocked,"
    # inferred from volume of same-family evidence, not a single tag match.
    confirmed_blocked_generalizable: int = 0
    confirmed_blocked_other: int = 0

    @property
    def confirmed_total(self) -> int:
        return self.confirmed_success + self.confirmed_blocked_generalizable + self.confirmed_blocked_other

    @property
    def looks_saturated(self) -> bool:
        """True once this family has accumulated real, resolved evidence
        (not just attempts still pending a verdict) and NONE of it
        succeeded. Requires at least 2 CONFIRMED outcomes -- a single
        refusal is a real fact about one attempt (per ACTIVELY_REFUSED's
        own non-generalizable status), not yet a pattern about the whole
        family; two or more, still zero successes, is."""
        return self.confirmed_total >= 2 and self.confirmed_success == 0


@dataclass(frozen=True)
class TargetBeliefState:
    """Everything Aginiti currently believes about the target, derived
    purely from Claims already on the graph. See module docstring for the
    "must be reconstructable from the SSG" rule this enforces.

    capabilities/trust_edges/mission_outcomes/defender_controls/
    partial_progress are all frozensets of CLAIM KEYS (not prose) -- a
    caller that wants a human-readable form calls `summarize()`, which is
    explicitly documented (belief_state.py's own rule, reused here) as
    HUMAN-FACING ONLY; no planner term may branch on its output."""
    capabilities: frozenset[str] = field(default_factory=frozenset)
    trust_edges: frozenset[str] = field(default_factory=frozenset)
    mission_outcomes: frozenset[str] = field(default_factory=frozenset)
    defender_controls: frozenset[str] = field(default_factory=frozenset)
    # HYPOTHESIZED (not yet CONFIRMED/REFUTED) claim keys -- genuine
    # "investigation in progress" state per the user's own item 5
    # ("partial disclosure," "prerequisite for another attack established"
    # both surface here before they resolve one way or the other).
    partial_progress: frozenset[str] = field(default_factory=frozenset)
    family_stats: dict[str, FamilyStats] = field(default_factory=dict)
    # Same shape as family_stats, ONE LEVEL FINER -- keyed by `Operator.
    # technique_cluster` (see that field's own docstring) rather than
    # `attack_category`. Added 2026-08-14 alongside `technique_cluster` in
    # direct response to the same exp28 postmortem: `attack_category` (11
    # broad categories) cannot tell "5 near-duplicate wrapper templates
    # around the same underlying question" apart from "a genuinely
    # different technique that happens to share the same broad category" --
    # this can, but ONLY for operators an author has explicitly opted into
    # a shared cluster. Untagged operators (the common case) simply never
    # appear here, exactly like family_stats already treats an untagged
    # attack_category as a no-op.
    cluster_stats: dict[str, FamilyStats] = field(default_factory=dict)
    open_hypotheses: tuple["Hypothesis", ...] = field(default_factory=tuple)

    def family(self, attack_category: str | None) -> FamilyStats:
        """Never raises -- an untagged/never-seen family returns the
        all-zero default, matching BranchSignal's own "no belief yet"
        convention."""
        if attack_category is None:
            return FamilyStats()
        return self.family_stats.get(attack_category, FamilyStats())

    def cluster(self, technique_cluster: str | None) -> FamilyStats:
        """Same never-raises convention as family() -- an operator with no
        technique_cluster (the common, default case) always reads as the
        all-zero default, meaning this mechanism stays a true no-op for it."""
        if technique_cluster is None:
            return FamilyStats()
        return self.cluster_stats.get(technique_cluster, FamilyStats())

    def unexplored_families(self, known_families: frozenset[str]) -> frozenset[str]:
        """Which of `known_families` (typically every attack_category the
        CURRENT operator library's effects declare) has zero attempts so
        far -- the concrete "investigate another boundary/path" set."""
        return frozenset(f for f in known_families if self.family(f).attempted == 0)

    def summarize(self) -> dict:
        """HUMANS/REPORTING ONLY (belief_state.py's own rule, reused
        verbatim here) -- a JSON-safe structured dict, never prose a
        planner term reads. Used by decision_trace.py to build an
        explanation whose every claim traces back to one of these fields,
        not to free text a model generated."""
        return {
            "capabilities": sorted(self.capabilities),
            "trust_edges": sorted(self.trust_edges),
            "mission_outcomes": sorted(self.mission_outcomes),
            "defender_controls": sorted(self.defender_controls),
            "partial_progress": sorted(self.partial_progress),
            "families": {
                name: {
                    "attempted": stats.attempted,
                    "confirmed_success": stats.confirmed_success,
                    "confirmed_blocked_generalizable": stats.confirmed_blocked_generalizable,
                    "confirmed_blocked_other": stats.confirmed_blocked_other,
                    "looks_saturated": stats.looks_saturated,
                }
                for name, stats in sorted(self.family_stats.items())
            },
            "clusters": {
                name: {
                    "attempted": stats.attempted,
                    "confirmed_success": stats.confirmed_success,
                    "confirmed_blocked_generalizable": stats.confirmed_blocked_generalizable,
                    "confirmed_blocked_other": stats.confirmed_blocked_other,
                    "looks_saturated": stats.looks_saturated,
                }
                for name, stats in sorted(self.cluster_stats.items())
            },
            "open_hypotheses": [h.statement for h in self.open_hypotheses],
        }

    @staticmethod
    def _operator_family_map(library) -> dict[str, str]:
        """Maps every claim key ANY operator in `library` declares (success
        OR failure) to that operator's own overall family -- the SAME
        "success effect's tag first, else a failure effect's" rule
        `aginiti/graph/novelty.py`'s `operator_family_diversification()`
        uses. Exists because the codebase-wide convention (every existing
        operator pack, `data_exposure.py` included) only tags
        `attack_category` on SUCCESS effects, never failure ones -- a
        CONFIRMED failure claim's OWN `ssg.claim_attack_category` entry is
        therefore almost always empty, even though the operator that
        produced it unambiguously belongs to a family. Falling back to
        `ssg.claim_attack_category` alone (as an earlier version of this
        method did) silently failed to recognize saturation from repeated
        FAILURES specifically -- caught by manually tracing exp22's own
        ablation scenario before trusting this mechanism, not assumed."""
        mapping: dict[str, str] = {}
        for op in library:
            family = None
            for effect in op.effects_success:
                if effect.attack_category is not None:
                    family = effect.attack_category
                    break
            if family is None:
                for effect in op.effects_failure:
                    if effect.attack_category is not None:
                        family = effect.attack_category
                        break
            if family is None:
                continue
            for effect in (*op.effects_success, *op.effects_failure):
                mapping.setdefault(effect.key, family)
        return mapping

    @staticmethod
    def _operator_cluster_map(library) -> dict[str, str]:
        """Same construction as `_operator_family_map`, one level finer:
        maps every claim key an operator declares (success OR failure) to
        that operator's own `technique_cluster` -- but ONLY for operators
        that actually set one. An operator with `technique_cluster=None`
        (the default, common case) contributes nothing here, exactly
        mirroring how an untagged `attack_category` contributes nothing to
        `_operator_family_map`."""
        mapping: dict[str, str] = {}
        for op in library:
            if op.technique_cluster is None:
                continue
            for effect in (*op.effects_success, *op.effects_failure):
                mapping.setdefault(effect.key, op.technique_cluster)
        return mapping

    @classmethod
    def from_ssg(cls, ssg: "SecurityStateGraph", library=None) -> "TargetBeliefState":
        """Pure function: rebuilds the whole state from ssg.claims every
        call. `library` is optional; when given, it does two things: (1)
        lets `attempted` count an operator's own attempt even when its
        resolved effect is still HYPOTHESIZED, and (2) -- the more
        consequential one -- lets a CONFIRMED FAILURE claim be correctly
        attributed to its operator's family even though the codebase-wide
        convention leaves failure effects untagged (see
        `_operator_family_map`'s own docstring). Without `library`, family
        stats fall back to `ssg.claim_attack_category` alone, which
        under-counts failures specifically -- a real, known degradation,
        not a silent one."""
        from aginiti.core.graph.ssg import (
            CATEGORY_CAPABILITY,
            CATEGORY_DEFENDER_CONTROL,
            CATEGORY_MISSION_OUTCOME,
            CATEGORY_TRUST_EDGE,
        )

        capabilities: set[str] = set()
        trust_edges: set[str] = set()
        mission_outcomes: set[str] = set()
        defender_controls: set[str] = set()
        partial_progress: set[str] = set()
        counts: dict[str, dict[str, int]] = {}
        cluster_counts: dict[str, dict[str, int]] = {}
        operator_family_map = cls._operator_family_map(library) if library is not None else {}
        operator_cluster_map = cls._operator_cluster_map(library) if library is not None else {}

        def _bump(counter: dict[str, dict[str, int]], group: str, field_name: str) -> None:
            entry = counter.setdefault(group, {"attempted": 0, "confirmed_success": 0,
                                                 "confirmed_blocked_generalizable": 0,
                                                 "confirmed_blocked_other": 0})
            entry[field_name] += 1

        # Pass 1: every RESOLVED claim's own category/family bucket.
        seen_keys: set[str] = set()
        for key in ssg.claim_category:
            if key in seen_keys:
                continue
            seen_keys.add(key)
            claim = ssg.current_claim(key)
            if claim is None:
                continue
            category = ssg.claim_category.get(key)
            family = ssg.claim_attack_category.get(key) or operator_family_map.get(key)

            if claim.status == ClaimStatus.HYPOTHESIZED:
                partial_progress.add(key)
                continue

            # CONFIRMED/REFUTED from here on -- a resolved outcome.
            if category == CATEGORY_CAPABILITY and claim.status == ClaimStatus.CONFIRMED:
                capabilities.add(key)
            elif category == CATEGORY_TRUST_EDGE and claim.status == ClaimStatus.CONFIRMED:
                trust_edges.add(key)
            elif category == CATEGORY_MISSION_OUTCOME and claim.status == ClaimStatus.CONFIRMED:
                mission_outcomes.add(key)
            elif category == CATEGORY_DEFENDER_CONTROL and claim.status == ClaimStatus.CONFIRMED:
                defender_controls.add(key)

            cluster = operator_cluster_map.get(key)
            is_success = category == CATEGORY_MISSION_OUTCOME and claim.status == ClaimStatus.CONFIRMED
            is_blocked = category == CATEGORY_DEFENDER_CONTROL and claim.status == ClaimStatus.CONFIRMED
            diagnosis = ssg.claim_failure_diagnosis.get(key) if is_blocked else None
            generalizable_block = is_blocked and is_generalizable(diagnosis)

            for counter, group in ((counts, family), (cluster_counts, cluster)):
                if group is None:
                    continue
                _bump(counter, group, "attempted")
                if is_success:
                    _bump(counter, group, "confirmed_success")
                elif is_blocked:
                    _bump(counter, group, "confirmed_blocked_generalizable" if generalizable_block
                          else "confirmed_blocked_other")

        family_stats = {name: FamilyStats(**vals) for name, vals in counts.items()}
        cluster_stats = {name: FamilyStats(**vals) for name, vals in cluster_counts.items()}

        open_hyps = tuple(
            h for h in ssg.hypotheses.values()
            if h.status.value == "open"
        ) if hasattr(ssg, "hypotheses") else ()

        return cls(
            capabilities=frozenset(capabilities),
            trust_edges=frozenset(trust_edges),
            mission_outcomes=frozenset(mission_outcomes),
            defender_controls=frozenset(defender_controls),
            partial_progress=frozenset(partial_progress),
            family_stats=family_stats,
            cluster_stats=cluster_stats,
            open_hypotheses=open_hyps,
        )

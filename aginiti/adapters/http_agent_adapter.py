"""HTTPAgentAdapter -- BaseAdapter wrapper around AgentEndpoint (Phase 2,
plans/phase2-operator-wrapping.md Slice A).

The bridge that lets a `run_campaign()`-driven planner and a wrapped deep
attack (IKEA/SECRET/MIA -- Slice B onward) share ONE real HTTP session
against a stateful target, instead of two independent connections
drifting out of sync. `AgentEndpoint` (aginiti/connectors/endpoint.py) is
the one connection shape in this codebase that actually owns a persistent
`requests.Session` (built once, reused for every call) -- every concrete
BaseAdapter today (HardenedAgentAdapter, AnythingLLMAdapter, ...) instead
builds a fresh `requests.request(...)` per call for a different reason
(multi-persona/workspace routing), so wrapping AgentEndpoint here, rather
than making BaseAttack speak BaseAdapter, is what actually solves the
session-sharing problem plans/integration-plan.md flagged as unsolved.

Construction takes an EXISTING AgentEndpoint instance, never a URL --
this class never builds its own session. Whoever wires up a campaign
(a script, Slice E's deep_attack_operators.py factory, ...) constructs
one AgentEndpoint and hands it to both this adapter (for the campaign/
planner side) and to a deep-attack's `endpoint=` kwarg (Slice B) --
same object, same session, same cookies/keep-alive.

Channel handling -- deliberately narrower than the plan doc's original
sketch: AgentEndpoint's simple flat-JSON contract (this class exists
specifically for "simple HTTP RAG interfaces" per integration-plan.md's
own description) has exactly ONE real chat endpoint. Silently mapping an
arbitrary `channel` string onto AgentEndpoint's `endpoint` path parameter
(e.g. channel="slack" -> POST /slack) would be guessing at a URL path
that almost certainly doesn't exist on a real target, trading a clear
error for a confusing 404 deep inside requests' own exception. BaseAdapter's
own docstring already covers this case explicitly: "a real target may
expose none [additional channels], in which case its operator library
only ever uses 'direct'" -- so this adapter enforces exactly that,
matching InjecAgentPoolAdapter's precedent of raising a clear ValueError
for an unsupported channel rather than silently guessing.
"""
from __future__ import annotations

from aginiti.adapters.base import SendResult
from aginiti.connectors.endpoint import AgentEndpoint


class HTTPAgentAdapter:
    """BaseAdapter (aginiti/adapters/base.py) wrapping a caller-supplied
    AgentEndpoint. Only `channel="direct"` is supported -- see this
    module's own docstring for why that's a deliberate scope limit, not
    an oversight."""

    def __init__(self, endpoint: AgentEndpoint):
        # Public on purpose (not name-mangled/private): this is the exact
        # seam Slice B's deep-attack bridge reaches through to hand the
        # SAME AgentEndpoint instance to a wrapped BaseAttack subclass via
        # its new `endpoint=` constructor kwarg.
        self.endpoint = endpoint

    def send(self, channel: str, prompt: str) -> SendResult:
        if channel != "direct":
            raise ValueError(
                f"HTTPAgentAdapter only supports channel='direct' (got {channel!r}) -- "
                "it wraps a single flat-JSON HTTP endpoint (AgentEndpoint), which has no "
                "concept of additional attack-surface channels like 'slack'/'github_issue'. "
                "An operator library targeting this adapter should only ever declare "
                "channel='direct' operators."
            )
        try:
            final_text = self.endpoint.chat(prompt)
            return SendResult(final_text=final_text, tool_trace=[], is_synthetic=False)
        except Exception as e:  # noqa: BLE001 -- deliberately broad, same discipline as
            # ObservationAdapter._send()'s own backstop and every other concrete adapter's
            # TargetUnavailable-style handling: a target-side failure (connection refused,
            # timeout, malformed response, an unrecoverable 4xx/5xx after AgentEndpoint's
            # own retry budget is exhausted) must become a synthetic SendResult, never an
            # unhandled exception that crashes the whole campaign. ObservationAdapter._send()
            # would also catch this if it slipped through, but catching it here too gives a
            # more specific, adapter-authored message -- the same "backstop, not a
            # replacement for adapter-level handling where it adds value" pattern documented
            # on ObservationAdapter._send() itself.
            return SendResult(
                final_text=f"[Aginiti: HTTPAgentAdapter target request failed: "
                           f"{type(e).__name__}: {e}]",
                tool_trace=[], is_synthetic=True,
            )

    def ground_truth_mission_achieved(self) -> bool:
        """Stubbed False for Phase 2 (plans/phase2-operator-wrapping.md
        Open Question 5, explicit decision, not an oversight): AgentEndpoint
        is a generic flat-JSON HTTP client with no concept of "did the
        target actually reach a compromised state" -- unlike DVLA's real
        transaction-DB check or AnythingLLM's canary-token check, there is
        no independent oracle to consult here.

        Real consequence, worth stating plainly rather than leaving implicit:
        this is the SAME adapter instance used for every operator in a
        campaign that includes a wrapped deep attack, not just the deep-
        attack operator itself -- so EVERY ExecutionResult.ground_truth_
        mission_achieved in such a campaign reads False, including for
        ordinary prompt-type operators that ran through this same adapter.
        This is a real, accepted limitation of Phase 2 (ground-truth
        verification is unavailable for the whole campaign when this
        adapter is in use), not a bug -- revisit only if a future phase
        needs a real oracle for plain HTTP targets."""
        return False

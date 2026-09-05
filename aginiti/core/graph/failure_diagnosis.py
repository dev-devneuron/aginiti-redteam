"""Structured failure-diagnosis taxonomy -- built at explicit
user direction: "A failure
shouldn't simply mean 'attack failed.' It should produce structured
evidence: 'this tool exists, but employee-level credentials cannot invoke
it,' or 'the agent follows retrieved instructions, but the collector
blocks outbound network access,' or 'RAG poisoning succeeded, but the
poisoned instruction cannot cross the approval boundary.' ... Then the
planner should ask: given what I just learned, what attack path is now
more promising?"

Deliberately a SEPARATE, additive dimension from CATEGORY_* (ssg.py),
security_boundary.py, owasp_llm_taxonomy.py, and attack_category.py --
same discipline as all four: this answers "WHY did this specific attempt
fail, structurally," a question none of the other four dimensions answer
(CATEGORY_DEFENDER_CONTROL says a claim IS a defender-graph fact; this
says WHAT KIND of defensive mechanism produced it). An effect can carry
this alongside any of the other four independently.

Before this, every operator's failure effect confirms one generic
"*_blocked"/"*_not_retrieved" claim with no diagnostic detail about WHY --
`system_prompt_extraction_blocked`, `anythingllm_rag_injection_not_
retrieved`, `mcp_plugin_exfiltration_blocked`, etc. are all structurally
identical facts to the planner: "this exact claim key is now CONFIRMED,"
nothing more. A red-teamer facing a real target treats a privilege
rejection, a network-egress block, and an approval-gate rejection as three
DIFFERENT pieces of evidence with different implications for what to try
next -- a privilege rejection means "try a lower-privilege path or a
different credential," a network block means "the poisoning half may have
worked, only egress is stopped," an approval-gate rejection means "the
attack reached a human checkpoint, which is a different kind of finding
than being rejected outright."

GROUNDING (per this project's own "cite real sources" discipline): the
"single-trajectory identifiability gap" -- a negative result on one
observed trajectory doesn't by itself distinguish "the environment
genuinely enforces this boundary" from "the evaluator simply didn't find
an alternative path yet" -- is a real, named problem in recent LLM-agent
evaluation literature, motivating post-failure diagnosis as an ACTIVE
evidence-acquisition problem rather than a terminal verdict. Structured-
diagnosis pipelines (failure localization -> cross-signal fusion ->
structured diagnosis record, with explicit attribution of which mechanism
was responsible) are an emerging pattern for exactly this kind of richer
failure reporting in agent evaluation.

Deliberately opt-in and DELIBERATELY SMALL, same discipline as every prior
taxonomy module in this repo: only 5 categories, each one directly
traceable to one of the user's own named examples or an existing, already-
observed pattern in this codebase's own failure claims (see each
category's own comment for its provenance) -- not a speculative, larger
taxonomy invented ahead of evidence that finer categories are needed."""
from __future__ import annotations

# The three categories the user named directly, verbatim, as examples of
# STRUCTURAL, GENERALIZABLE failure evidence -- "this mechanism blocks
# things," true independent of which specific operator triggered it.
BLOCKED_BY_PRIVILEGE = "blocked_by_privilege"          # "tool exists, but this credential/access level cannot invoke it"
BLOCKED_BY_NETWORK_EGRESS = "blocked_by_network_egress"  # "the poisoning/injection succeeded, but outbound egress is stopped"
BLOCKED_BY_APPROVAL_GATE = "blocked_by_approval_gate"    # "reached a human/second-step checkpoint, not rejected outright"

# Two categories that are NOT structurally generalizable -- see
# aginiti/planner/aginiti_planner.py's failure_evidence_penalty() for
# exactly why these two never demote another candidate, while the three
# above can.
NOT_RETRIEVED = "not_retrieved"        # content/instruction simply never reached context this attempt -- tells you
                                        # nothing about whether a DIFFERENT operator's content would (matches this
                                        # project's existing, already-observed pattern: anythingllm_rag_injection_
                                        # not_retrieved's own docstring already flags this exact ambiguity)
ACTIVELY_REFUSED = "actively_refused"  # the target explicitly declined THIS specific request -- a real fact about
                                        # this attempt, but not (without further evidence) proof the SAME refusal
                                        # applies to a differently-phrased or differently-channeled attempt

ALL_DIAGNOSES = (
    BLOCKED_BY_PRIVILEGE, BLOCKED_BY_NETWORK_EGRESS, BLOCKED_BY_APPROVAL_GATE,
    NOT_RETRIEVED, ACTIVELY_REFUSED,
)

# The subset that generalizes -- a CONFIRMED claim carrying one of these
# tags is real, structural evidence that the SAME blocking mechanism
# plausibly applies to any OTHER candidate whose own prospective failure
# would carry the identical tag. Deliberately conservative (3 of 5, not
# all 5): failure_evidence_penalty() is a NEGATIVE utility term, so this
# taxonomy is more conservative here than every prior "only ever helps"
# additive term in this codebase -- a false demotion is a real cost
# (skipping a genuinely viable path), so only the categories with a clear
# structural/boundary-level story earn the ability to demote.
GENERALIZABLE_DIAGNOSES = (BLOCKED_BY_PRIVILEGE, BLOCKED_BY_NETWORK_EGRESS, BLOCKED_BY_APPROVAL_GATE)

DIAGNOSIS_DESCRIPTIONS = {
    BLOCKED_BY_PRIVILEGE: "The action/tool genuinely exists and was reached, but the current credential/"
                           "access level lacks permission to invoke it -- a privilege boundary, not a "
                           "content or detection failure.",
    BLOCKED_BY_NETWORK_EGRESS: "The upstream steps (poisoning, injection, tool invocation) succeeded, but "
                                "an outbound network call was specifically blocked -- the compromise got "
                                "everywhere except across the network boundary.",
    BLOCKED_BY_APPROVAL_GATE: "The attempt reached a human-in-the-loop or second-step confirmation "
                               "checkpoint rather than being rejected outright -- a different, generally "
                               "harder-to-bypass finding than an immediate refusal.",
    NOT_RETRIEVED: "The planted/injected content simply never reached the model's context this attempt -- "
                   "uninformative about whether the underlying mechanism is defended at all.",
    ACTIVELY_REFUSED: "The target explicitly declined this specific request -- a real fact about this one "
                       "attempt, not yet evidence about a differently-phrased or differently-channeled one.",
}


def validate(diagnosis: str) -> bool:
    return diagnosis in ALL_DIAGNOSES


def is_generalizable(diagnosis: str | None) -> bool:
    return diagnosis is not None and diagnosis in GENERALIZABLE_DIAGNOSES

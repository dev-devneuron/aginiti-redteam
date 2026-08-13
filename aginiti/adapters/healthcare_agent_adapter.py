"""BaseAdapter for `benchmarks/scaled_evals/agents/healthcare_agent` -- a
vendored (see `.gitignore`/`docs/AGINITI_OVERVIEW.md`) RAG chatbot target
over the real HealthCareMagic-1k dataset (`lavita/ChatDoctor-HealthCareMagic-
100k`, the same dataset the IKEA paper, arXiv:2505.15420, benchmarks
against). One FastAPI surface, no auth, a single `/chat` endpoint -- the
simplest of the two new targets, and the one with only a soft, prompt-level
guardrail (no RBAC, no output redaction, no rate limiting).

Exception-safety follows the exact pattern established for
`AnythingLLMAdapter` (`aginiti/adapters/anythingllm_adapter.py`) and the
2026-08-12 hardening pass (`docs/ENGINEERING_HARDENING_PASS.md`): every
`requests` failure and every non-JSON body is classified into
`TargetUnavailable` and converted to an explicit `is_synthetic=True`
non-event by `send()`'s wrapper, never left to crash the campaign
uncaught.

Ground truth: `aginiti/adapters/scaled_evals_ground_truth.py`'s verbatim
N-word-window index against the real, locally-seeded
`healthcaremagic_1k.json` -- an exact, deterministic, target-agnostic
check for "did the model recite real patient-consultation text back,"
independent of the target's own soft guardrail wording and independent of
any LLM judge.

**2026-08-14 addition:** an optional SECOND, still fully deterministic
oracle -- `FuzzyDisclosureIndex` (same module) -- catches paraphrased
disclosure the strict exact-match index misses by construction (a real,
live-confirmed gap: `healthcare_agent`'s own memory-leakage finding
reformatted a real record into bullet points, defeating the 12-word exact
match while a human reader would immediately recognize it as the same
content). `ground_truth_mission_achieved()` stays TRUE-if-exact-OR-fuzzy
when a fuzzy index is supplied; `exact_disclosure_confirmed()`/
`fuzzy_disclosure_confirmed()` expose the two signals separately for
anyone who needs to distinguish "certain, verbatim" from "strong,
paraphrased" evidence rather than a collapsed boolean. Passing no fuzzy
index at all (the original constructor signature) reproduces the exact-
match-only behavior unchanged -- backward compatible by construction, not
by special-casing.
"""
from __future__ import annotations

import requests

from aginiti.adapters.base import SendResult
from aginiti.adapters.scaled_evals_ground_truth import FuzzyDisclosureIndex, VerbatimDisclosureIndex

DEFAULT_BASE_URL = "http://localhost:8003"


class TargetUnavailable(Exception):
    """Raised internally for any target-side failure -- connection refused/
    timeout (target down/unreachable), a non-2xx HTTP response, or a
    non-JSON body. Caught uniformly by send(), same discipline as every
    other adapter hardened in the 2026-08-12 pass."""


def _classify_requests_error(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.Timeout):
        return "target request timed out"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "could not connect to target (target down or unreachable)"
    if isinstance(exc, requests.exceptions.HTTPError):
        return f"target returned an HTTP error: {exc}"
    return f"target request failed: {exc}"


class HealthcareAgentAdapter:
    """BaseAdapter for a running healthcare_agent instance. Single-persona,
    single-channel target -- `channel` must be "direct"."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 60.0,
                 disclosure_index: VerbatimDisclosureIndex | None = None,
                 fuzzy_disclosure_index: FuzzyDisclosureIndex | None = None):
        self.base_url = base_url
        self.timeout = timeout
        self._raw_responses: list[str] = []
        self._disclosure_index = disclosure_index
        self._fuzzy_disclosure_index = fuzzy_disclosure_index

    def send(self, channel: str, prompt: str) -> SendResult:
        if channel != "direct":
            raise ValueError(f"HealthcareAgentAdapter only supports channel='direct', got {channel!r}")
        try:
            data = self._post_chat(prompt)
        except TargetUnavailable as e:
            final_text = f"[Aginiti: target unavailable -- {e}]"
            self._raw_responses.append(final_text)
            return SendResult(final_text=final_text, tool_trace=[], is_synthetic=True)

        final_text = data.get("response") or ""
        self._raw_responses.append(final_text)
        return SendResult(final_text=final_text, tool_trace=[])

    def _post_chat(self, prompt: str) -> dict:
        try:
            resp = requests.post(
                f"{self.base_url}/chat",
                timeout=self.timeout,
                json={"message": prompt},
            )
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            raise TargetUnavailable(_classify_requests_error(e)) from e
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise TargetUnavailable(_classify_requests_error(e)) from e
        try:
            return resp.json()
        except (ValueError, requests.exceptions.JSONDecodeError) as e:
            raise TargetUnavailable(f"target returned a malformed (non-JSON) response: {e}") from e

    def ground_truth_mission_achieved(self) -> bool:
        """True on EITHER oracle firing (exact OR fuzzy, when a fuzzy index
        is supplied) -- re-scanned fresh from `self._raw_responses` on
        every call (not incrementally tracked in send()) so this stays a
        genuinely independent check, not one that could silently drift
        from what an operator's extractor already decided. See module
        docstring for the two oracles' distinct confidence levels."""
        return self.exact_disclosure_confirmed() or self.fuzzy_disclosure_confirmed()

    def exact_disclosure_confirmed(self) -> bool:
        if self._disclosure_index is None:
            return False
        return any(self._disclosure_index.check(text) is not None for text in self._raw_responses)

    def fuzzy_disclosure_confirmed(self) -> bool:
        if self._fuzzy_disclosure_index is None:
            return False
        return any(self._fuzzy_disclosure_index.check(text) is not None for text in self._raw_responses)

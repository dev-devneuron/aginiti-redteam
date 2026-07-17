import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

import litellm

logger = logging.getLogger(__name__)

# Silences litellm's own "Give Feedback / Get Help" boilerplate print block,
# which it emits to STDOUT (not through logging, so it can't be filtered by
# log level) on every mapped exception, including every rate-limit retry —
# in a rate-limit storm this floods the console with dozens of repeats of
# the same unhelpful block, burying our own [RATE LIMIT]/[LLM #N] progress
# logs. litellm's own Router sets this same flag for the same reason
# (litellm/router.py, "prevents 'Give Feedback/Get help' message ... Relevant
# Issue: https://github.com/BerriAI/litellm/issues/5942"). Purely a print-
# suppression flag — does not affect retry behavior or error handling.
litellm.suppress_debug_info = True

# Rate-limit retry (added 2026-07-13). litellm normalizes every provider's
# rate-limit response into litellm.RateLimitError regardless of underlying
# provider (Gemini, Groq, OpenAI, Anthropic, ... — verified: it subclasses
# openai.RateLimitError, which is litellm's common exception hierarchy for
# all providers), so this is provider-agnostic by construction, not a
# Groq-specific patch. Free-tier RPM/TPM limits reset on a rolling 60s
# window; litellm's own num_retries backoff (below) retries too fast to
# survive that, so this wraps litellm.completion with real sleep-based
# backoff on top.
#
# Revised 2026-07-13 (same day, second pass): a live run hit a Groq **TPD**
# (tokens-per-day) limit, not RPM/TPM — its "try again in ..." hints were
# multi-minute (7m12s, 2m4.416s, 4m19.2s, ...), and the OLD version of this
# regex/cap combo failed in two ways: (1) the regex only captured a single
# "<number><unit>" token, so a compound "7m12s" string matched just "7m" and
# silently dropped the "12s"; (2) _RATE_LIMIT_DEFAULT_WAIT_SECONDS was used
# as a hard ceiling on top of that, capping every parsed wait at 60s even
# though the provider had just said it needed 7+ minutes. Every retry then
# woke up early, hit the still-active TPD limit again, and after 5 attempts
# (5 wasted minutes) the loop raised uncaught. RPM/TPM windows genuinely do
# reset within 60s, but TPD-scale waits do not — one constant can't describe
# both, so the two are now handled differently: waits below
# _RATE_LIMIT_FAILOVER_THRESHOLD_SECONDS are slept through (as before); waits
# at or above it are treated as "this provider needs a long recovery *right
# now*" and immediately try the configured fallback provider instead of
# blocking, since sleeping out a genuinely multi-minute-to-hours TPD window
# inline is not a reasonable thing for an attack run to do.
_RATE_LIMIT_WAIT_HINT_RE = re.compile(
    r"try again in\s+((?:[\d.]+\s*(?:ms|s|m)(?![a-z])\s*)+)", re.IGNORECASE
)
# (?![a-z]) instead of \b: in a compact compound duration like "7m12s" there
# is no word-boundary between the "m" and the "1" that follows (both are \w
# characters), so a trailing \b would silently fail to match the "7m" part
# at all (verified — this was a real bug in an earlier version of this
# regex). The negative lookahead only rejects unit letters that are actually
# the start of a longer word (e.g. avoids misreading "500 milliseconds" as
# "500 minutes"), while still accepting a unit immediately followed by the
# next token's digits.
_RATE_LIMIT_UNIT_RE = re.compile(r"([\d.]+)\s*(ms|s|m)(?![a-z])", re.IGNORECASE)
_RATE_LIMIT_MAX_RETRIES = 5
# Per-minute rate limits (RPM/TPM) universally reset within 60s regardless
# of provider — used as the fallback wait when a provider's error message
# doesn't include a parseable "try again in X" hint at all.
_RATE_LIMIT_DEFAULT_WAIT_SECONDS = 60.0
# Waits parsed at or above this are assumed to be a longer-cycle limit (e.g.
# Groq's TPD) rather than a per-minute one — see revision note above. Chosen
# as a round number comfortably above any real RPM/TPM reset (60s) but well
# below the multi-minute TPD waits actually observed (2-7+ minutes).
_RATE_LIMIT_FAILOVER_THRESHOLD_SECONDS = 90.0


def _rate_limit_wait_seconds(exc: Exception) -> float:
    """
    Parse a provider's rate-limit error message for a "try again in ..." hint,
    summing every "<number><unit>" token found (handles compound durations
    like "7m12s" or "1m6.527999999s", not just a single unit) — Groq and
    several other OpenAI-compatible providers include this. Falls back to a
    flat 60s if no hint is found at all.

    Returns the REAL parsed duration (+1s safety margin), uncapped — callers
    decide what to do with a long duration (see
    _RATE_LIMIT_FAILOVER_THRESHOLD_SECONDS and ``_call``'s failover logic)
    rather than this function silently truncating it.
    """
    match = _RATE_LIMIT_WAIT_HINT_RE.search(str(exc))
    if not match:
        return _RATE_LIMIT_DEFAULT_WAIT_SECONDS
    total_seconds = 0.0
    for value_str, unit in _RATE_LIMIT_UNIT_RE.findall(match.group(1)):
        value = float(value_str)
        if unit.lower() == "ms":
            total_seconds += value / 1000.0
        elif unit.lower() == "m":
            total_seconds += value * 60.0
        else:
            total_seconds += value
    # +1s safety margin — retrying at the *exact* reset instant risks
    # hitting the same window again due to clock/network skew.
    return max(total_seconds + 1.0, 1.0)


@dataclass
class LeakFinding:
    attack_type: str       # "DRA" / "MIA" / "FIA"
    tier_used: str         # "black_box" / "otel" / "logprobs"
    confidence: float      # 0.0 to 1.0
    confirmed: bool        # True for an actual data disclosure (pii/verbatim/
                            # sensitive_data leak_type at Tier 1, or an OTel
                            # retrieval-span match at Tier 2) — not merely a
                            # non-refused or topically-relevant response
    leaked_content: str
    probe_used: str
    trace_span_id: str     # "" if not applicable
    recommendation: str
    severity: str          # "critical" / "high" / "medium" / "low"
    # Added 2026-07-13 for LLM-as-judge leak classification (aginiti/attacks/
    # dra/ikea.py's _classify_leak). Additive only — all three default, so
    # every pre-existing LeakFinding(...) call site keeps working unchanged.
    full_response: str = ""    # complete agent response, for analyst review
                                # (leaked_content holds only the evidence quote)
    leak_type: str = "unknown"  # "none"/"schema"/"pii"/"sensitive_data"/"verbatim"/"unknown"
    reasoning: str = ""         # one-sentence classifier explanation


class BaseAttack(ABC):
    def __init__(self, target_url: str, llm_provider: str,
                 api_key: str, otel_ingester=None,
                 fallback_llm_provider: Optional[str] = None,
                 fallback_api_key: Optional[str] = None):
        # fallback_llm_provider/fallback_api_key added 2026-07-13 (additive,
        # both default None — every existing call site keeps working
        # unchanged). See _init_llm's docstring for when the fallback is used.
        self.target_url = target_url
        self.llm = self._init_llm(
            llm_provider, api_key, fallback_llm_provider, fallback_api_key
        )
        self.otel = otel_ingester

    @abstractmethod
    def execute_black_box(self, **kwargs) -> list[LeakFinding]:
        ...

    @abstractmethod
    def execute_with_traces(self, **kwargs) -> list[LeakFinding]:
        ...

    def execute(self, **kwargs) -> list[LeakFinding]:
        if self.otel:
            return self.execute_with_traces(**kwargs)
        return self.execute_black_box(**kwargs)

    def _init_llm(
        self,
        llm_provider: str,
        api_key: str,
        fallback_llm_provider: Optional[str] = None,
        fallback_api_key: Optional[str] = None,
    ):
        # Returns a callable: (messages: list[dict], **kwargs) -> str
        # llm_provider is a LiteLLM model string, e.g.:
        #   "gemini/gemini-3.5-flash", "openai/gpt-4o", "ollama/llama3"
        # LiteLLM routes to the correct provider automatically.
        #
        # fallback_llm_provider/fallback_api_key (added 2026-07-13): a second
        # LiteLLM model string tried when the PRIMARY provider reports a
        # rate-limit wait so long (>= _RATE_LIMIT_FAILOVER_THRESHOLD_SECONDS,
        # e.g. a Groq TPD/daily-quota message) that blocking inline isn't
        # reasonable. Not sticky — every call still tries the primary first;
        # if the primary's daily quota is genuinely exhausted this means
        # every subsequent call in the run will also fail over, which costs
        # one extra doomed primary attempt per call but keeps the logic
        # simple and never leaves the object stuck on a fallback it might not
        # need once the primary recovers.
        _model = llm_provider
        _key = api_key or None
        _fallback_model = fallback_llm_provider
        _fallback_key = fallback_api_key or None

        def _attempt(model: str, key: Optional[str], messages: list[dict], **kwargs) -> str:
            response = litellm.completion(
                model=model,
                messages=messages,
                api_key=key,
                **kwargs,
            )
            return response.choices[0].message.content

        def _call(messages: list[dict], **kwargs) -> str:
            # num_retries=0 (changed 2026-07-13, was 3): litellm's own retry
            # applies uniformly to every retryable exception, RateLimitError
            # included — but retrying a rate-limited call *immediately*
            # (litellm's internal backoff is sub-second, nowhere near a real
            # per-minute RPM/TPM reset window) just burns more requests
            # against a budget that's already exhausted, and each failed
            # sub-attempt prints its own noise. The loop below is the ONE
            # place rate-limit retries happen now, with real, informed waits.
            # This does mean a one-off non-rate-limit transient error (a
            # connection reset, a DNS blip) no longer gets an automatic
            # litellm-level retry — timeout=60 below still bounds a hung
            # connection, it just won't auto-retry it. Trade-off, not an
            # oversight: flag if you'd rather keep some retry budget for
            # pure network flakiness independent of rate-limit handling.
            # timeout: without this, a stalled connection (TCP/TLS established
            # but the server never finishes responding — common behind flaky
            # proxies/middleboxes) hangs forever with nothing to bound it.
            # kwargs.setdefault so a caller can still override per-call.
            kwargs.setdefault("num_retries", 0)
            kwargs.setdefault("timeout", 60)

            # Rate-limit retry (2026-07-13, revised same day for TPD-scale
            # waits — see the module comment above _RATE_LIMIT_WAIT_HINT_RE):
            # short waits (< failover threshold) are slept through with
            # escalating backoff, same as before. A wait AT OR ABOVE the
            # threshold is not slept through at all — it's treated as "this
            # provider needs real recovery time", and we immediately try the
            # fallback provider (if configured) for THIS call. If the
            # fallback also fails, or none is configured, we give up (break
            # out of the retry loop and raise) rather than blocking for
            # minutes — the caller (e.g. IKEAAttack.execute_black_box) is
            # responsible for degrading gracefully on that raise.
            last_exc: Optional[Exception] = None
            wait_s = 0.0
            for attempt in range(_RATE_LIMIT_MAX_RETRIES + 1):
                try:
                    return _attempt(_model, _key, messages, **kwargs)
                except litellm.RateLimitError as exc:
                    last_exc = exc
                    hinted_wait = _rate_limit_wait_seconds(exc)

                    if hinted_wait >= _RATE_LIMIT_FAILOVER_THRESHOLD_SECONDS:
                        if _fallback_model:
                            logger.warning(
                                "[RATE LIMIT] %s — reported wait %.1fs exceeds the "
                                "%.0fs failover threshold; failing over to backup "
                                "provider %r for this call instead of blocking.",
                                exc, hinted_wait,
                                _RATE_LIMIT_FAILOVER_THRESHOLD_SECONDS, _fallback_model,
                            )
                            try:
                                return _attempt(_fallback_model, _fallback_key, messages, **kwargs)
                            except Exception as fallback_exc:
                                logger.error(
                                    "[RATE LIMIT] Backup provider %r also failed: %s "
                                    "— giving up on this call.",
                                    _fallback_model, fallback_exc,
                                )
                                raise
                        logger.error(
                            "[RATE LIMIT] %s — reported wait %.1fs exceeds the %.0fs "
                            "failover threshold and no fallback_llm_provider is "
                            "configured — giving up rather than blocking the whole "
                            "run for minutes.",
                            exc, hinted_wait, _RATE_LIMIT_FAILOVER_THRESHOLD_SECONDS,
                        )
                        raise

                    if attempt >= _RATE_LIMIT_MAX_RETRIES:
                        break
                    wait_s = min(max(hinted_wait, wait_s * 2), _RATE_LIMIT_FAILOVER_THRESHOLD_SECONDS)
                    logger.warning(
                        "[RATE LIMIT] %s — waiting %.1fs before retry %d/%d …",
                        exc, wait_s, attempt + 1, _RATE_LIMIT_MAX_RETRIES,
                    )
                    time.sleep(wait_s)
                    logger.info(
                        "[RATE LIMIT] resumed after %.1fs — retrying now (attempt %d/%d)",
                        wait_s, attempt + 1, _RATE_LIMIT_MAX_RETRIES,
                    )

            raise last_exc  # type: ignore[misc]

        return _call

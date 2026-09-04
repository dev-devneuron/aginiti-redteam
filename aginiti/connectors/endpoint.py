import time
from typing import Callable, Optional

import requests


class AgentEndpoint:
    """
    Generic HTTP client for a black-box target agent.

    Default behavior (unchanged): POST ``{request_key: message}`` to
    ``base_url + endpoint`` (default ``/chat``), expect a flat JSON response
    with ``response_key`` holding the answer text. This covers this
    project's own reference agents and any target that speaks the same
    simple flat-JSON contract.

    ``headers``/``send_fn`` (additive — both default ``None`` and every
    existing call site's behavior is unchanged) exist to support targets
    that don't fit that contract: an authenticated target
    (API key / Bearer token) or one whose request/response shape isn't a
    flat ``{key: str}`` pair (e.g. an Ollama-style ``messages`` array
    request, or a stateful create-session-then-send-message flow). Neither
    parameter is specific to any one target — deliberately generic, since
    "any HTTP-accessible agent" (this project's Tier 1 promise) realistically
    includes authenticated ones. See ``benchmarks/scaled_evals/agents/onyx_target/connector.py``
    for the first real caller of both.

    ``rate_limit_wait_seconds`` (additive, default keeps prior behavior's
    *shape* but closes a real gap): a target that rate-limits (429) is a
    realistic defense — ``benchmarks/scaled_evals/agents/hardened_agent``
    is the first one this project actually has — and until now, a 429 was
    treated identically to every other 4xx: raised immediately, no retry
    ("4xx errors are the caller's fault"). That's correct for 400/401/403/404,
    but wrong for 429, whose entire meaning is "you're fine, just slow
    down." Found live while preparing a real MIA run against
    ``hardened_agent`` (its `RateLimiter` returns a bare 429 with no
    ``Retry-After`` header — see its own ``main.py``), not discovered via a
    dev-fixture test, since none of the dev-fixture/healthcare targets rate-
    limit at all. Behavior: a 429 response is retried (within the existing
    ``max_retries`` budget) using ``rate_limit_wait_seconds`` as the wait —
    honoring a standards-compliant ``Retry-After`` header if the target
    happens to send one, falling back to this default otherwise. Every
    other 4xx status is unchanged: raised immediately, no retry.
    """

    def __init__(
        self,
        base_url: str,
        request_key: str = "message",
        response_key: str = "response",
        timeout: int = 30,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        headers: Optional[dict] = None,
        send_fn: Optional[Callable[[requests.Session, str, str, int], str]] = None,
        rate_limit_wait_seconds: float = 65.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.request_key = request_key
        self.response_key = response_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.rate_limit_wait_seconds = rate_limit_wait_seconds
        # Static extra headers (e.g. {"Authorization": "Bearer ..."}), sent
        # on every request this class makes (chat AND check_reachable) —
        # some authenticated targets gate the health endpoint too.
        self.headers = headers or {}
        # Optional full override of HOW a chat request is made. Signature:
        # (session, url, message, timeout) -> response_text. When set, chat()
        # calls this instead of building the default flat-JSON payload —
        # still wrapped in the same retry/backoff loop below, so it must
        # raise requests.exceptions.HTTPError / ConnectionError / Timeout
        # for those to be retried the same way the default path is (a 4xx
        # HTTPError should still not be retried — same contract as below).
        self.send_fn = send_fn
        self._session = requests.Session()
        if self.headers:
            self._session.headers.update(self.headers)

    def chat(self, message: str, endpoint: str = "/chat") -> str:
        url = f"{self.base_url}{endpoint}"
        last_exc: Optional[Exception] = None
        # Set by a 429 response so the *next* iteration's sleep uses the
        # rate-limit wait instead of the normal exponential backoff — see
        # rate_limit_wait_seconds' docstring above.
        next_wait: Optional[float] = None

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                time.sleep(
                    next_wait if next_wait is not None
                    else self.backoff_factor * (2 ** (attempt - 1))
                )
                next_wait = None
            try:
                if self.send_fn is not None:
                    return self.send_fn(self._session, url, message, self.timeout)
                payload = {self.request_key: message}
                resp = self._session.post(url, json=payload, timeout=self.timeout)
                resp.raise_for_status()
                data = resp.json()
                if self.response_key not in data:
                    raise KeyError(
                        f"Response key '{self.response_key}' not found in response. "
                        f"Got keys: {list(data.keys())}"
                    )
                return data[self.response_key]
            except requests.exceptions.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 429:
                    # Rate-limited, not the caller's fault — retry with a
                    # real wait, honoring Retry-After if the target sends
                    # one (most simple in-memory limiters, including this
                    # project's own hardened_agent, don't).
                    retry_after = exc.response.headers.get("Retry-After")
                    try:
                        next_wait = float(retry_after) if retry_after else self.rate_limit_wait_seconds
                    except ValueError:
                        next_wait = self.rate_limit_wait_seconds
                    last_exc = exc
                    continue
                # Every other 4xx is the caller's fault — don't retry
                if exc.response is not None and exc.response.status_code < 500:
                    raise
                last_exc = exc
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as exc:
                last_exc = exc

        raise last_exc  # type: ignore[misc]

    def check_reachable(self, health_path: str = "/health", timeout: int = 5) -> bool:
        """
        Return True if the agent is TCP-reachable, False if the port is actively refused.

        Tries GET ``health_path`` (default ``/health``). Any HTTP response — even 404
        or 500 — is treated as "reachable" because we only care about TCP connectivity
        here. Only a ``ConnectionError`` (port refused / no listener) returns False.

        Used for a pre-flight check before anchor generation to avoid wasting LLM API
        credits when the agent process is not running.
        """
        try:
            self._session.get(
                f"{self.base_url}{health_path}", timeout=timeout, allow_redirects=False
            )
            return True  # any HTTP response = server is listening
        except requests.exceptions.ConnectionError:
            return False  # connection refused / no listener
        except Exception:
            # Timeout, SSL error, etc. — server may be up, let the real call decide.
            return True

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "AgentEndpoint":
        return self

    def __exit__(self, *_) -> None:
        self.close()

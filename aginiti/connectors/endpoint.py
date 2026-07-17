import time
from typing import Optional

import requests


class AgentEndpoint:
    def __init__(
        self,
        base_url: str,
        request_key: str = "message",
        response_key: str = "response",
        timeout: int = 30,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        self.base_url = base_url.rstrip("/")
        self.request_key = request_key
        self.response_key = response_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self._session = requests.Session()

    def chat(self, message: str, endpoint: str = "/chat") -> str:
        url = f"{self.base_url}{endpoint}"
        payload = {self.request_key: message}
        last_exc: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                time.sleep(self.backoff_factor * (2 ** (attempt - 1)))
            try:
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
                # 4xx errors are the caller's fault — don't retry
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

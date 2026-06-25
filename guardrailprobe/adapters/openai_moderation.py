"""guardrailprobe.adapters.openai_moderation — OpenAI Moderation API adapter."""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict

import httpx

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_API_URL = "https://api.openai.com/v1/moderations"
_MIN_CALL_INTERVAL = 1.1   # seconds; keeps RPM safely under OpenAI's 60 RPM free-tier limit
_QUOTA_COOLDOWN_SECS = 70.0


class OpenAIModerationAdapter:
    backend_name = "openai_moderation"

    _last_call: float = 0.0
    _call_lock: threading.Lock = threading.Lock()
    _quota_exhausted_until: float = 0.0

    def _api_key(self) -> str:
        return os.getenv("OPENAI_API_KEY", "").strip()

    def check_credentials(self) -> bool:
        return bool(self._api_key()) and time.monotonic() >= self._quota_exhausted_until

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        return "Set OPENAI_API_KEY environment variable."

    def _throttle(self) -> None:
        with self._call_lock:
            gap = _MIN_CALL_INTERVAL - (time.monotonic() - OpenAIModerationAdapter._last_call)
            if gap > 0:
                time.sleep(gap)
            OpenAIModerationAdapter._last_call = time.monotonic()

    def run_probe(self, payload: str) -> ProbeResponse:
        if not self.check_credentials():
            return ProbeResponse(
                action=ActionType.SKIPPED,
                latency_ms=0.0,
                raw_response={"skipped": True},
                backend=self.backend_name,
                status=AdapterStatus.NO_API_KEY,
                status_message=self.missing_credential_message(),
            )

        self._throttle()
        t0 = time.perf_counter()
        max_retries = 5
        data: Dict[str, Any] = {}

        for attempt in range(max_retries):
            try:
                resp = httpx.post(
                    _API_URL,
                    json={"input": payload},
                    headers={"Authorization": f"Bearer {self._api_key()}"},
                    timeout=15.0,
                )
                if resp.status_code == 429:
                    retry_after = resp.headers.get("retry-after")
                    try:
                        wait = float(retry_after) + 0.5
                    except (TypeError, ValueError):
                        wait = min(2 ** (attempt + 1), 60)
                    if attempt < max_retries - 1:
                        time.sleep(wait)
                        continue
                    OpenAIModerationAdapter._quota_exhausted_until = (
                        time.monotonic() + _QUOTA_COOLDOWN_SECS
                    )
                if resp.status_code in (401, 403):
                    latency = (time.perf_counter() - t0) * 1000
                    return ProbeResponse(
                        action=ActionType.SKIPPED,
                        latency_ms=latency,
                        raw_response={"error": f"HTTP {resp.status_code}"},
                        backend=self.backend_name,
                        status=AdapterStatus.NO_API_KEY,
                        status_message=f"Invalid API key (HTTP {resp.status_code}).",
                    )
                resp.raise_for_status()
                data = resp.json()
                break
            except httpx.HTTPStatusError as exc:
                latency = (time.perf_counter() - t0) * 1000
                logger.error("OpenAI Moderation HTTP error: %s", exc)
                return ProbeResponse(
                    action=ActionType.BLOCK,
                    latency_ms=latency,
                    raw_response={"error": str(exc)},
                    backend=self.backend_name,
                    status=AdapterStatus.ERROR,
                    status_message=str(exc),
                )
            except Exception as exc:
                latency = (time.perf_counter() - t0) * 1000
                logger.error("OpenAI Moderation error: %s", exc)
                return ProbeResponse(
                    action=ActionType.BLOCK,
                    latency_ms=latency,
                    raw_response={"error": str(exc)},
                    backend=self.backend_name,
                    status=AdapterStatus.ERROR,
                    status_message=str(exc),
                )

        latency = (time.perf_counter() - t0) * 1000
        results = data.get("results", [{}])
        flagged = bool(results[0].get("flagged", False)) if results else False
        action = ActionType.BLOCK if flagged else ActionType.ALLOW
        return ProbeResponse(
            action=action,
            latency_ms=round(latency, 2),
            raw_response=data,
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def health_check(self) -> Dict[str, Any]:
        if not self.check_credentials():
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        return {"status": "ok", "backend": self.backend_name}

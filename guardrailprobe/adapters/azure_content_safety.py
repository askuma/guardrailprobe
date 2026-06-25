"""guardrailprobe.adapters.azure_content_safety — Azure AI Content Safety adapter."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict

import httpx

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_API_VERSION = "2023-10-01"
_MAX_TEXT_CHARS = 10_000


def _severity_to_action(max_severity: int) -> ActionType:
    if max_severity >= 4:
        return ActionType.BLOCK
    if max_severity >= 2:
        return ActionType.ESCALATE
    return ActionType.ALLOW


class AzureContentSafetyAdapter:
    backend_name = "azure_content_safety"

    def _endpoint(self) -> str:
        return os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT", "").strip()

    def _api_key(self) -> str:
        return os.getenv("AZURE_CONTENT_SAFETY_KEY", "").strip()

    def check_credentials(self) -> bool:
        return bool(self._endpoint() and self._api_key())

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        return (
            "Set AZURE_CONTENT_SAFETY_ENDPOINT and AZURE_CONTENT_SAFETY_KEY "
            "environment variables."
        )

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

        endpoint = self._endpoint().rstrip("/")
        url = f"{endpoint}/contentsafety/text:analyze?api-version={_API_VERSION}"
        safe_text = payload[:_MAX_TEXT_CHARS]
        t0 = time.perf_counter()

        for attempt in range(2):
            try:
                resp = httpx.post(
                    url,
                    json={"text": safe_text},
                    headers={"Ocp-Apim-Subscription-Key": self._api_key()},
                    timeout=30.0,
                )
                if resp.status_code in (401, 403):
                    return ProbeResponse(
                        action=ActionType.SKIPPED,
                        latency_ms=(time.perf_counter() - t0) * 1000,
                        raw_response={"error": f"HTTP {resp.status_code}"},
                        backend=self.backend_name,
                        status=AdapterStatus.NO_API_KEY,
                        status_message=f"Invalid credentials (HTTP {resp.status_code}).",
                    )
                resp.raise_for_status()
                data = resp.json()
                break
            except httpx.TimeoutException:
                if attempt == 0:
                    continue
                latency = (time.perf_counter() - t0) * 1000
                return ProbeResponse(
                    action=ActionType.BLOCK,
                    latency_ms=latency,
                    raw_response={"error": "timeout"},
                    backend=self.backend_name,
                    status=AdapterStatus.ERROR,
                    status_message="Azure Content Safety timed out.",
                )
            except Exception as exc:
                latency = (time.perf_counter() - t0) * 1000
                logger.error("Azure Content Safety error: %s", exc)
                return ProbeResponse(
                    action=ActionType.BLOCK,
                    latency_ms=latency,
                    raw_response={"error": str(exc)},
                    backend=self.backend_name,
                    status=AdapterStatus.ERROR,
                    status_message=str(exc),
                )

        latency = (time.perf_counter() - t0) * 1000
        max_severity = 0
        for cat in data.get("categoriesAnalysis", []):
            max_severity = max(max_severity, int(cat.get("severity", 0)))

        action = _severity_to_action(max_severity)
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

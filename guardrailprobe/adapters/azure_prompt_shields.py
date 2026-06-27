"""guardrailprobe.adapters.azure_prompt_shields — Azure Prompt Shields adapter."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict

import httpx

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_API_VERSION = "2024-09-01"


class AzurePromptShieldsAdapter:
    backend_name = "azure_prompt_shields"

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
            "environment variables (shared with azure_content_safety)."
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
        url = (
            f"{endpoint}/contentsafety/text:shieldPrompt"
            f"?api-version={_API_VERSION}"
        )
        t0 = time.perf_counter()

        # Azure Prompt Shields enforces a 10 000-character limit on userPrompt.
        send_payload = payload[:10000]
        for attempt in range(2):
            try:
                resp = httpx.post(
                    url,
                    json={"userPrompt": send_payload, "documents": []},
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
                if resp.status_code == 400:
                    detail = resp.text[:300] if resp.text else "no body"
                    logger.warning(
                        "Azure Prompt Shields 400 — probe content rejected: %s", detail
                    )
                    return ProbeResponse(
                        action=ActionType.SKIPPED,
                        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                        raw_response={"error": "HTTP 400", "detail": detail},
                        backend=self.backend_name,
                        status=AdapterStatus.ERROR,
                        status_message=f"HTTP 400: {detail}",
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
                    status_message="Azure Prompt Shields timed out.",
                )
            except Exception as exc:
                latency = (time.perf_counter() - t0) * 1000
                logger.error("Azure Prompt Shields error: %s", exc)
                return ProbeResponse(
                    action=ActionType.BLOCK,
                    latency_ms=latency,
                    raw_response={"error": str(exc)},
                    backend=self.backend_name,
                    status=AdapterStatus.ERROR,
                    status_message=str(exc),
                )

        latency = (time.perf_counter() - t0) * 1000
        attack_detected = bool(
            data.get("userPromptAnalysis", {}).get("attackDetected", False)
        )
        action = ActionType.BLOCK if attack_detected else ActionType.ALLOW
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

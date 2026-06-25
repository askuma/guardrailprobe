"""guardrailprobe.adapters.lakera — Lakera Guard v2 REST adapter."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict

import httpx

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_INPUT_URL = "https://api.lakera.ai/v2/guard"


class LakeraAdapter:
    backend_name = "lakera"

    def _api_key(self) -> str:
        return os.getenv("LAKERA_GUARD_API_KEY", "").strip()

    def check_credentials(self) -> bool:
        return bool(self._api_key())

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        return "Set LAKERA_GUARD_API_KEY environment variable."

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

        t0 = time.perf_counter()
        try:
            resp = httpx.post(
                _INPUT_URL,
                json={"messages": [{"role": "user", "content": payload}], "breakdown": True},
                headers={"Authorization": f"Bearer {self._api_key()}"},
                timeout=10.0,
            )
            if resp.status_code in (401, 403):
                return ProbeResponse(
                    action=ActionType.SKIPPED,
                    latency_ms=(time.perf_counter() - t0) * 1000,
                    raw_response={"error": f"HTTP {resp.status_code}"},
                    backend=self.backend_name,
                    status=AdapterStatus.NO_API_KEY,
                    status_message=f"Invalid API key (HTTP {resp.status_code}).",
                )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            latency = (time.perf_counter() - t0) * 1000
            logger.error("Lakera HTTP error: %s", exc)
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
            logger.error("Lakera error: %s", exc)
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=latency,
                raw_response={"error": str(exc)},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message=str(exc),
            )

        latency = (time.perf_counter() - t0) * 1000
        flagged = bool(data.get("flagged", False))
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

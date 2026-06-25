"""guardrailprobe.adapters.llm_guard — Protect AI LLM Guard adapter.

Runs PromptInjection + Toxicity input scanners locally — no API key required.
Requires: pip install 'guardrailprobe[llm_guard]'
"""

from __future__ import annotations

import importlib.util
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_LLM_GUARD_SDK: bool = importlib.util.find_spec("llm_guard") is not None

_scanners: Optional[List[Any]] = None
_scanners_lock = threading.Lock()


def _get_scanners() -> Optional[List[Any]]:
    global _scanners
    if _scanners is not None:
        return _scanners
    with _scanners_lock:
        if _scanners is not None:
            return _scanners
        try:
            from llm_guard.input_scanners import PromptInjection, Toxicity  # noqa: PLC0415
            _scanners = [PromptInjection(), Toxicity()]
            return _scanners
        except Exception as exc:
            logger.error("LLM Guard scanner init failed: %s", exc)
            return None


class LLMGuardAdapter:
    backend_name = "llm_guard"

    def check_credentials(self) -> bool:
        return _LLM_GUARD_SDK

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        return (
            "LLM Guard SDK not installed. "
            "Run: pip install 'guardrailprobe[llm_guard]'"
        )

    def run_probe(self, payload: str) -> ProbeResponse:
        if not _LLM_GUARD_SDK:
            return ProbeResponse(
                action=ActionType.SKIPPED,
                latency_ms=0.0,
                raw_response={"skipped": True},
                backend=self.backend_name,
                status=AdapterStatus.NO_API_KEY,
                status_message=self.missing_credential_message(),
            )

        scanners = _get_scanners()
        if scanners is None:
            return ProbeResponse(
                action=ActionType.SKIPPED,
                latency_ms=0.0,
                raw_response={"skipped": True, "error": "scanner init failed"},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message="LLM Guard scanner initialisation failed.",
            )

        t0 = time.perf_counter()
        try:
            from llm_guard import scan_prompt  # noqa: PLC0415
            sanitized, results_valid, results_score = scan_prompt(scanners, payload)
            flagged = not all(results_valid.values())
            score = max(results_score.values()) if results_score else 0.0
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            logger.error("LLM Guard error: %s", exc)
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=latency,
                raw_response={"error": str(exc)},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message=str(exc),
            )

        latency = (time.perf_counter() - t0) * 1000
        action = ActionType.BLOCK if flagged else ActionType.ALLOW
        return ProbeResponse(
            action=action,
            latency_ms=round(latency, 2),
            raw_response={"flagged": flagged, "score": score, "valid": results_valid},
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def health_check(self) -> Dict[str, Any]:
        if not _LLM_GUARD_SDK:
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        return {"status": "ok", "backend": self.backend_name}

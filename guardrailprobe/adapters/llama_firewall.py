"""guardrailprobe.adapters.llama_firewall — Meta LlamaFirewall adapter.

Runs Meta's PromptGuard 2 model locally — no API key required.
Requires: pip install 'guardrailprobe[llamafirewall]'
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import time
from typing import Any, Dict

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_LLAMAFIREWALL_SDK: bool = importlib.util.find_spec("llamafirewall") is not None


class LlamaFirewallAdapter:
    backend_name = "llama_firewall"

    def check_credentials(self) -> bool:
        return _LLAMAFIREWALL_SDK

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        return (
            "LlamaFirewall SDK not installed. "
            "Run: pip install 'guardrailprobe[llamafirewall]'"
        )

    def _scan(self, payload: str):
        from llamafirewall import LlamaFirewall, UserMessage  # noqa: PLC0415

        async def _run():
            return await LlamaFirewall().scan(UserMessage(content=payload))

        try:
            return asyncio.run(_run())
        except RuntimeError:
            import concurrent.futures  # noqa: PLC0415
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, _run()).result(timeout=30)

    def run_probe(self, payload: str) -> ProbeResponse:
        if not _LLAMAFIREWALL_SDK:
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
            result = self._scan(payload)
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            logger.error("LlamaFirewall error: %s", exc)
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=latency,
                raw_response={"error": str(exc)},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message=str(exc),
            )

        latency = (time.perf_counter() - t0) * 1000
        decision_str = str(getattr(result, "decision", "")).upper()
        flagged = "BLOCK" in decision_str or "HUMAN_REVIEW" in decision_str
        score = float(getattr(result, "score", 0.0))
        action = ActionType.BLOCK if flagged else ActionType.ALLOW
        return ProbeResponse(
            action=action,
            latency_ms=round(latency, 2),
            raw_response={"decision": decision_str, "score": score},
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def health_check(self) -> Dict[str, Any]:
        if not _LLAMAFIREWALL_SDK:
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        return {"status": "ok", "backend": self.backend_name}

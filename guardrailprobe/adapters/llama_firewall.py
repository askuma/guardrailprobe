"""guardrailprobe.adapters.llama_firewall — Meta LlamaFirewall adapter.

Runs Meta's PromptGuard 2 model locally — no API key required, but the model
must be available (either cached locally, or HF_TOKEN set to download it).

Requires: pip install llamafirewall --target ./site-packages --ignore-installed
Model:    meta-llama/Llama-Prompt-Guard-2-86M (gated — accept license on HuggingFace)
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import os
import time
from typing import Any, Dict

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_LLAMAFIREWALL_SDK: bool = importlib.util.find_spec("llamafirewall") is not None

_MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"


def _hf_token() -> str:
    return (os.getenv("HF_TOKEN") or os.getenv("HUGGING_FACE_HUB_TOKEN") or "").strip()


def _model_cached() -> bool:
    """Return True only when model weights are present and usable."""
    try:
        from huggingface_hub import try_to_load_from_cache  # noqa: PLC0415
        # config.json may exist even when the download was incomplete —
        # verify that actual weight files are present.
        for weight_file in ("model.safetensors", "pytorch_model.bin"):
            if try_to_load_from_cache(_MODEL_ID, weight_file) is not None:
                return True
        return False
    except Exception:
        return False


class LlamaFirewallAdapter:
    backend_name = "llama_firewall"

    def check_credentials(self) -> bool:
        if not _LLAMAFIREWALL_SDK:
            return False
        return bool(_hf_token()) or _model_cached()

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        if not _LLAMAFIREWALL_SDK:
            return (
                "LlamaFirewall SDK not installed. "
                "Install: python3.12 -m pip install llamafirewall "
                "--target ./site-packages --ignore-installed"
            )
        return (
            f"Model {_MODEL_ID} not cached and HF_TOKEN not set. "
            "Accept the model license on huggingface.co, then add HF_TOKEN to .env."
        )

    def _scan(self, payload: str):
        from llamafirewall import LlamaFirewall, UserMessage  # noqa: PLC0415

        token = _hf_token()
        if token:
            os.environ.setdefault("HF_TOKEN", token)

        async def _run():
            return await LlamaFirewall().scan(UserMessage(content=payload))

        try:
            return asyncio.run(_run())
        except RuntimeError:
            import concurrent.futures  # noqa: PLC0415
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, _run()).result(timeout=60)

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
            result = self._scan(payload)
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            err_str = str(exc)
            # Incomplete model download — weights missing or meta-tensor (no data)
            if any(k in err_str for k in (
                "no file named pytorch_model.bin",
                "model.safetensors",
                "meta tensor",
                "to_empty",
            )):
                logger.warning(
                    "LlamaFirewall: model weights incomplete or corrupt — "
                    "re-run: rm -rf ~/.cache/huggingface/hub/models--meta-llama--Llama-Prompt-Guard-2-86M "
                    "then restart the container with HF_TOKEN set."
                )
                return ProbeResponse(
                    action=ActionType.SKIPPED,
                    latency_ms=latency,
                    raw_response={"error": err_str},
                    backend=self.backend_name,
                    status=AdapterStatus.NO_API_KEY,
                    status_message="Model weights incomplete. Delete cache and re-download with HF_TOKEN.",
                )
            logger.error("LlamaFirewall error: %s", exc)
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=latency,
                raw_response={"error": err_str},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message=err_str,
            )

        latency = (time.perf_counter() - t0) * 1000
        decision_str = str(getattr(result, "decision", "")).upper()
        flagged = "BLOCK" in decision_str or "HUMAN_REVIEW" in decision_str
        score = float(getattr(result, "score", 0.0))
        return ProbeResponse(
            action=ActionType.BLOCK if flagged else ActionType.ALLOW,
            latency_ms=round(latency, 2),
            raw_response={"decision": decision_str, "score": score},
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def health_check(self) -> Dict[str, Any]:
        if not self.check_credentials():
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        return {"status": "ok", "backend": self.backend_name,
                "model": _MODEL_ID, "cached": _model_cached()}

"""guardrailprobe.adapters.llama_firewall — Meta LlamaFirewall adapter.

Runs Meta's PromptGuard 2 model locally — no API key required once the model
is cached. Set HF_TOKEN to download it on first run (accept the model license
on HuggingFace first). The model is cached in HF_HOME (/app/hf_models in Docker).

Requires: pip install llamafirewall --target ./site-packages --ignore-installed
Model:    meta-llama/Llama-Prompt-Guard-2-86M (gated — accept license on HuggingFace)
"""

from __future__ import annotations

import importlib.util
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_LLAMAFIREWALL_SDK: bool = importlib.util.find_spec("llamafirewall") is not None

_MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"

# Cache the first scan error so subsequent probes skip model loading and
# fail-closed immediately rather than re-attempting on every probe.
_scan_error: Optional[str] = None

# Cached LlamaFirewall instance — loaded once on first probe to avoid
# reloading the 86M model from disk for every single probe call.
_lf_instance: Optional[Any] = None
_lf_lock = threading.Lock()


def _hf_token() -> str:
    return (os.getenv("HF_TOKEN") or os.getenv("HUGGING_FACE_HUB_TOKEN") or "").strip()


def _model_cached() -> bool:
    """Return True when model weights are present in the HF cache."""
    try:
        from huggingface_hub import try_to_load_from_cache  # noqa: PLC0415
        for weight_file in ("model.safetensors", "pytorch_model.bin"):
            if try_to_load_from_cache(_MODEL_ID, weight_file) is not None:
                return True
        return False
    except Exception:
        return False


class LlamaFirewallAdapter:
    backend_name = "llama_firewall"

    def check_credentials(self) -> bool:
        # Mirrors monorepo: only gate on SDK presence. Model is loaded on
        # first probe; if unavailable the scan raises and we fail-closed (BLOCK).
        return _LLAMAFIREWALL_SDK

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        return (
            "LlamaFirewall SDK not installed. "
            "Install: python3.12 -m pip install llamafirewall "
            "--target ./site-packages --ignore-installed"
        )

    def _get_lf(self):
        """Return a cached LlamaFirewall instance (loads model on first call)."""
        global _lf_instance
        if _lf_instance is None:
            with _lf_lock:
                if _lf_instance is None:
                    from llamafirewall import LlamaFirewall  # noqa: PLC0415
                    token = _hf_token()
                    if token:
                        os.environ.setdefault("HF_TOKEN", token)
                    _lf_instance = LlamaFirewall()
        return _lf_instance

    def _scan(self, payload: str):
        from llamafirewall import UserMessage  # noqa: PLC0415

        lf = self._get_lf()

        # lf.scan() is synchronous but internally calls asyncio.run() for each scanner.
        # Run it in a dedicated fresh thread so there is no running event loop in that
        # thread, which would cause "asyncio.run() cannot be called from a running event
        # loop" when the benchmark thread pool reuses threads from NeMo's asyncio.run().
        import concurrent.futures  # noqa: PLC0415
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lf.scan, UserMessage(content=payload)).result(timeout=60)

    def run_probe(self, payload: str) -> ProbeResponse:
        global _scan_error

        if not _LLAMAFIREWALL_SDK:
            return ProbeResponse(
                action=ActionType.SKIPPED,
                latency_ms=0.0,
                raw_response={"skipped": True},
                backend=self.backend_name,
                status=AdapterStatus.NO_API_KEY,
                status_message=self.missing_credential_message(),
            )

        # If a previous probe already failed to load the model, skip the
        # expensive scan attempt and fail-closed immediately.
        if _scan_error is not None:
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=0.1,
                raw_response={"error": _scan_error, "cached_failure": True},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message=_scan_error,
            )

        t0 = time.perf_counter()
        try:
            result = self._scan(payload)
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            err_str = str(exc)[:200]
            # Cache the error so remaining probes skip model loading.
            _scan_error = err_str
            logger.error("LlamaFirewall error (will skip model load for remaining probes): %s", exc)
            # Fail-closed: any scan failure is treated as a detected threat.
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
        if not _LLAMAFIREWALL_SDK:
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        return {"status": "ok", "backend": self.backend_name,
                "model": _MODEL_ID, "cached": _model_cached()}

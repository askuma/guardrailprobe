"""guardrailprobe.adapters.presidio — Microsoft Presidio PII detection adapter."""

from __future__ import annotations

import importlib
import importlib.util
import logging
import time
from typing import Any, Dict, Optional

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_PRESIDIO_SDK: bool = (
    importlib.util.find_spec("presidio_analyzer") is not None
    and importlib.util.find_spec("presidio_anonymizer") is not None
)

_analyzer: Optional[Any] = None
_anonymizer: Optional[Any] = None
_init_lock = __import__("threading").Lock()


def _load_presidio() -> bool:
    global _analyzer, _anonymizer
    if _analyzer is not None:
        return True
    if not _PRESIDIO_SDK:
        return False
    with _init_lock:
        if _analyzer is not None:
            return True
        try:
            pa = importlib.import_module("presidio_analyzer")
            pan = importlib.import_module("presidio_anonymizer")
            _PatternRecognizer = pa.pattern_recognizer.PatternRecognizer
            _Pattern = pa.pattern_recognizer.Pattern

            class _SecretsRecognizer(_PatternRecognizer):
                PATTERNS = [
                    _Pattern("OpenAI key",     r"\bsk-[A-Za-z0-9]{20,}\b",          0.9),
                    _Pattern("Anthropic key",  r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b",   0.9),
                    _Pattern("GitHub token",   r"\bghp_[A-Za-z0-9]{36}\b",           0.9),
                    _Pattern("AWS access key", r"\bAKIA[A-Z0-9]{16}\b",              0.9),
                    _Pattern("Bearer token",   r"\bBearer\s+[A-Za-z0-9\._\-]{20,}\b", 0.8),
                    _Pattern("Generic secret", r"\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S{8,}", 0.7),
                ]
                def __init__(self):
                    super().__init__(supported_entity="SECRET_KEY", patterns=self.PATTERNS)

            _analyzer = pa.AnalyzerEngine()
            _analyzer.registry.add_recognizer(_SecretsRecognizer())
            _anonymizer = pan.AnonymizerEngine()
            logger.info("Presidio SDK loaded — PII + secrets detection active.")
            return True
        except Exception as exc:
            logger.warning("Presidio SDK init failed: %s", exc)
            return False


class PresidioAdapter:
    backend_name = "presidio"

    def check_credentials(self) -> bool:
        return _PRESIDIO_SDK

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        return (
            "Presidio SDK not installed. "
            "Run: pip install 'guardrailprobe[presidio]' && "
            "python -m spacy download en_core_web_lg"
        )

    def run_probe(self, payload: str) -> ProbeResponse:
        if not _load_presidio():
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
            results = _analyzer.analyze(text=payload, language="en")
            flagged = len(results) > 0
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            logger.error("Presidio error: %s", exc)
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=latency,
                raw_response={"error": str(exc)},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message=str(exc),
            )

        latency = (time.perf_counter() - t0) * 1000
        action = ActionType.REDACT if flagged else ActionType.ALLOW
        entities = [{"entity": r.entity_type, "score": round(r.score, 3)} for r in results]
        return ProbeResponse(
            action=action,
            latency_ms=round(latency, 2),
            raw_response={"entities": entities},
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def health_check(self) -> Dict[str, Any]:
        if not _PRESIDIO_SDK:
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        return {"status": "ok", "backend": self.backend_name}

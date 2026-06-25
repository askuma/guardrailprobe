"""guardrailprobe.adapters.guardrails_ai — GuardrailsAI framework adapter."""

from __future__ import annotations

import importlib
import importlib.util
import logging
import re
import time
from typing import Any, Dict, List, Tuple

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_GUARDRAILSAI_SDK: bool = importlib.util.find_spec("guardrails") is not None

_DEFAULT_VALIDATORS: List[str] = ["DetectPII", "SecretsPresent", "ToxicLanguage"]

# Shared regex scorer used when SDK is unavailable or hub validators are missing.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I),
    re.compile(r"disregard\s+(the\s+)?above", re.I),
    re.compile(r"you\s+are\s+now\s+DAN", re.I),
    re.compile(r"do\s+anything\s+now", re.I),
    re.compile(r"(system\s+prompt|instructions?):\s*override", re.I),
    re.compile(r"jailbreak\s+mode", re.I),
    re.compile(r"developer\s+mode", re.I),
    re.compile(r"reveal\s+(your\s+)?(system\s+prompt|instructions?)", re.I),
]

_HARMFUL_PATTERNS = [
    re.compile(r"how\s+to\s+(make|build|create)\s+a\s+bomb", re.I),
    re.compile(r"how\s+to\s+hack\s+into", re.I),
    re.compile(r"write\s+ransomware", re.I),
    re.compile(r"generate\s+phishing", re.I),
    re.compile(r"create\s+(a\s+)?virus", re.I),
]


def _regex_score(text: str) -> Tuple[bool, float]:
    all_patterns = _INJECTION_PATTERNS + _HARMFUL_PATTERNS
    matches = [p for p in all_patterns if p.search(text)]
    if matches:
        score = min(0.5 + 0.05 * len(matches), 0.99)
        return True, round(score, 4)
    return False, 0.0


class GuardrailsAIAdapter:
    backend_name = "guardrails_ai"

    def _build_guard(self, validators: List[str]):
        g = importlib.import_module("guardrails")
        hub = importlib.import_module("guardrails.hub")
        guard = g.Guard()
        loaded: List[str] = []
        for name in validators:
            try:
                cls = getattr(hub, name, None)
                if cls is None:
                    continue
                guard = guard.use(cls(on_fail="noop"))
                loaded.append(name)
            except Exception as exc:
                logger.debug("GuardrailsAI: could not load validator %r: %s", name, exc)
        return guard, bool(loaded)

    def check_credentials(self) -> bool:
        return True  # regex fallback always available

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN

    def missing_credential_message(self) -> str:
        return ""  # always available

    def run_probe(self, payload: str) -> ProbeResponse:
        t0 = time.perf_counter()
        sdk_flagged = False
        sdk_score = 0.0

        if _GUARDRAILSAI_SDK:
            try:
                guard, hub_loaded = self._build_guard(_DEFAULT_VALIDATORS)
                if hub_loaded:
                    outcome = guard.validate(payload)
                    sdk_flagged = not bool(outcome.validation_passed)
                    sdk_score = 0.0 if not sdk_flagged else 0.85
            except Exception as exc:
                logger.debug("GuardrailsAI validate raised: %s", exc)
                sdk_flagged = True
                sdk_score = 0.85
        else:
            logger.debug("guardrails-ai SDK not installed — using regex fallback")

        # Regex scorer for defence in depth
        regex_flagged, regex_score = _regex_score(payload)
        flagged = sdk_flagged or regex_flagged
        score = max(sdk_score, regex_score)

        latency = (time.perf_counter() - t0) * 1000
        action = ActionType.BLOCK if flagged else ActionType.ALLOW
        return ProbeResponse(
            action=action,
            latency_ms=round(latency, 2),
            raw_response={"flagged": flagged, "score": score, "sdk_used": _GUARDRAILSAI_SDK},
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def health_check(self) -> Dict[str, Any]:
        return {"status": "ok", "backend": self.backend_name,
                "sdk": _GUARDRAILSAI_SDK}

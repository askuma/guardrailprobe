"""guardrailprobe.adapters.guardrails_ai — GuardrailsAI framework adapter.

Mirrors the monorepo's policy-rail-config approach: a static validator policy is
compiled into a Guard at adapter initialisation time. The SDK result is used as-is;
regex runs ONLY as a standalone fallback when the SDK is entirely unavailable.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_GUARDRAILSAI_SDK: bool = importlib.util.find_spec("guardrails") is not None

# ── Policy rail config ────────────────────────────────────────────────────────
# Equivalent to what PolicyCompiler.compile_to_guardrails_yaml() would produce
# for an all-category probe run. Each entry maps to a guardrails-ai hub validator.
# Validators absent from the installed hub are silently skipped; if none load
# the adapter falls back to regex (see below).

_POLICY_RAIL_CONFIG: List[Dict[str, str]] = [
    {"hub_name": "PromptInjection",  "on_fail": "noop"},
    {"hub_name": "ToxicLanguage",    "on_fail": "noop"},
    {"hub_name": "DetectPII",        "on_fail": "noop"},
    {"hub_name": "SecretsPresent",   "on_fail": "noop"},
]

# ── Regex fallback (SDK unavailable path only) ────────────────────────────────

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


# ── Adapter ───────────────────────────────────────────────────────────────────

class GuardrailsAIAdapter:
    backend_name = "guardrails_ai"

    def __init__(self) -> None:
        self._guard: Optional[Any] = None
        self._hub_validators_loaded: List[str] = []
        if _GUARDRAILSAI_SDK:
            self._guard, self._hub_validators_loaded = self._compile_guard()

    def _compile_guard(self) -> Tuple[Optional[Any], List[str]]:
        """Build a Guard from _POLICY_RAIL_CONFIG, skipping missing hub validators.

        Returns (None, []) if the guardrails package itself fails to import
        (e.g. broken transitive dependency like pydantic_core) so the adapter
        degrades to regex without crashing the registry.
        """
        try:
            g = importlib.import_module("guardrails")
            hub = importlib.import_module("guardrails.hub")
        except ImportError as exc:
            logger.warning(
                "guardrails-ai import failed (%s) — using regex fallback", exc
            )
            return None, []

        guard = g.Guard()
        loaded: List[str] = []
        for entry in _POLICY_RAIL_CONFIG:
            name = entry["hub_name"]
            on_fail = entry.get("on_fail", "noop")
            try:
                cls = getattr(hub, name, None)
                if cls is None:
                    logger.debug("guardrails hub: %r not found — skipped", name)
                    continue
                guard = guard.use(cls(on_fail=on_fail))
                loaded.append(name)
            except Exception as exc:
                logger.debug("guardrails hub: could not load %r: %s", name, exc)
        if loaded:
            logger.debug("guardrails guard compiled with validators: %s", loaded)
        else:
            logger.warning("guardrails hub: no validators loaded — will use regex fallback")
        return guard, loaded

    def check_credentials(self) -> bool:
        return True  # regex fallback always available

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN

    def missing_credential_message(self) -> str:
        return ""

    def run_probe(self, payload: str) -> ProbeResponse:
        t0 = time.perf_counter()

        if _GUARDRAILSAI_SDK and self._hub_validators_loaded:
            # SDK path: run hub validators AND regex; flag if either detects a threat.
            # Hub validators (DetectPII, SecretsPresent) catch data-exfil probes;
            # regex catches injection/jailbreak probes not covered by those validators.
            try:
                outcome = self._guard.validate(payload)  # type: ignore[union-attr]
                sdk_flagged = not bool(outcome.validation_passed)
            except Exception as exc:
                logger.debug("guardrails validate raised: %s", exc)
                sdk_flagged = True
            regex_flagged, _regex_score_val = _regex_score(payload)
            flagged = sdk_flagged or regex_flagged
            score = 0.85 if flagged else 0.0
            sdk_used = True
        else:
            # Regex-only fallback — SDK not installed or no hub validators loaded.
            if _GUARDRAILSAI_SDK:
                logger.debug("guardrails-ai SDK present but no hub validators — using regex fallback")
            else:
                logger.debug("guardrails-ai SDK not installed — using regex fallback")
            flagged, score = _regex_score(payload)
            sdk_used = False

        latency = (time.perf_counter() - t0) * 1000
        return ProbeResponse(
            action=ActionType.BLOCK if flagged else ActionType.ALLOW,
            latency_ms=round(latency, 2),
            raw_response={
                "flagged": flagged,
                "score": score,
                "sdk_used": sdk_used,
                "validators": self._hub_validators_loaded,
            },
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "backend": self.backend_name,
            "sdk": _GUARDRAILSAI_SDK,
            "validators_loaded": self._hub_validators_loaded,
        }

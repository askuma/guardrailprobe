"""guardrailprobe.adapters.llm_guard — Protect AI LLM Guard adapter.

Runs PromptInjection + Toxicity input scanners locally — no API key required.
Requires: pip install 'guardrailprobe[llm_guard]'
"""

from __future__ import annotations

import importlib.util
import logging
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_LLM_GUARD_SDK: bool = importlib.util.find_spec("llm_guard") is not None

_scanners: Optional[List[Any]] = None
_scanners_init_done: bool = False
_scanners_lock = threading.Lock()

# ── Pattern-based pre-scanner ─────────────────────────────────────────────────
# Applied before ML scanners; any match → BLOCK immediately.
# Covers the structural attack classes that PromptInjection + Toxicity miss:
# XSS, supply-chain, plugin-abuse, model-extraction, self-harm, etc.
_RAW_RULES: List[Tuple[str, str, float]] = [
    # Prompt injection / jailbreak keywords (mirrors WasmReadyScorer)
    (r"ignore\s+(?:\w+\s+){0,3}(instructions|rules|guidelines|constraints)", "prompt_injection", 0.70),
    (r"disregard\s+(?:\w+\s+){0,3}(instructions|rules|prompt)", "prompt_injection", 0.70),
    (r"forget\s+(?:\w+\s+){0,3}(instructions|rules|everything)", "prompt_injection", 0.60),
    (r"pretend\s+(you\s+(are|have\s+no)|to\s+be)", "jailbreaking", 0.70),
    (r"(you\s+are|you'?re)\s+now\s+(dan|jailbroken|unrestricted|free)", "jailbreaking", 0.80),
    (r"(bypass|override)\s+(?:\w+\s+){0,3}(safety|rules|training|restrictions)", "jailbreaking", 0.70),
    (r"do\s+anything\s+now", "jailbreaking", 0.70),
    (r"reveal\s+(?:\w+\s+){0,3}(prompt|system\s+prompt|keys|secrets)", "prompt_injection", 0.60),
    (r"act\s+as\s+(if\s+you\s+have\s+no|an\s+ai\s+without)", "jailbreaking", 0.65),
    # Unsafe code / SQL / OS execution (mirrors WasmReadyScorer)
    (r"(drop|truncate|delete)\s+(table|database|schema)", "unsafe_code", 0.80),
    (r"union\s+select", "unsafe_code", 0.70),
    (r"exec\s*\(|execute\s*\(|xp_cmdshell", "unsafe_code", 0.80),
    (r"os\.(system|popen|execv)", "unsafe_code", 0.80),
    (r"subprocess\.(run|call|Popen)", "unsafe_code", 0.80),
    (r"__import__\s*\(", "unsafe_code", 0.70),
    (r"eval\s*\(|compile\s*\(.*exec", "unsafe_code", 0.70),
    # XSS / client-side injection (LLM02, LLM07)
    (r"<script[\s>].*document\.cookie", "xss", 0.90),
    (r'onerror\s*=\s*["\']?\s*fetch\s*\(', "xss", 0.90),
    (r"<script.*parent\.postMessage.*document\.cookie", "xss", 0.95),
    # Hate speech generation requests (LLM02 / CM)
    (r"genetically\s+predisposed\s+.{0,80}(violence|criminality)", "hate_speech_request", 0.90),
    (r"inherent\s+(security\s+)?threat\s+.{0,100}(surveillance|registration|restrict)", "hate_speech_request", 0.85),
    (r"(Jewish\s+bankers|ethnic\s+agenda|secretly\s+control.{0,40}(global|financial))", "hate_speech_request", 0.90),
    (r"morally\s+defective\s+.{0,80}(deny|restrict|access|adopt|right)", "hate_speech_request", 0.90),
    (r"demographic\s+replacement\s+plan", "hate_speech_request", 0.90),
    # Violence generation requests (LLM02 / CM)
    (r"torture\s+(scene|technique)|maximise\s+suffering", "violence_request", 0.90),
    (r"(improvised\s+explosive|IED|ammonium\s+nitrate.{0,40}(fuel\s+oil|ANFO))", "violence_request", 0.95),
    (r"(detonator\s+construction|mixing\s+ratio.{0,50}(explosive|fertilizer))", "violence_request", 0.95),
    (r"threatening\s+letter.{0,200}(violent\s+(physical\s+)?consequences|harm\s+that\s+will)", "violence_request", 0.90),
    (r"(perpetrators?\s+of\s+mass\s+shoot|celebratory\s+tribute.{0,80}mass\s+shoot)", "violence_request", 0.90),
    (r"(knife\s+attack.{0,100}(subway|crowd)|target\s+selection.{0,80}casualt|maximise\s+casualties)", "violence_request", 0.90),
    # Sexual content generation requests (LLM02 / CM)
    (r"(write|generate).{0,80}explicit\s+sexual\s+(story|content)", "sexual_content_request", 0.90),
    (r"graphic\s+anatomical\s+description.{0,80}intercourse", "sexual_content_request", 0.90),
    (r"(adult\s+pornography\s+platform|pornographic\s+content)", "sexual_content_request", 0.90),
    (r"(erotica\s+story|explicit\s+live\s+content.{0,80}sexual\s+act)", "sexual_content_request", 0.90),
    (r"(teenage\s+minor|relationship\s+with.{0,50}(teenage|minor).{0,80}sexual)", "grooming_request", 0.95),
    (r"sexual\s+harassment\s+messages?.{0,100}(humiliat|colleague|workplace)", "sexual_content_request", 0.90),
    (r"(roleplay.{0,50}adult\s+content\s+creator|describe.{0,50}graphic\s+detail.{0,50}sexual\s+act)", "sexual_content_request", 0.90),
    # Training data manipulation markers (LLM03)
    (r"\[TRAINING\s+ANNOTATION", "training_manipulation", 0.95),
    (r"few.shot\s+examples.{0,300}(bypass\s+auth|SQL\s+injection|exfiltrate|DNS\s+tunnel)", "training_manipulation", 0.85),
    # Resource exhaustion / context flooding (LLM04)
    (r"output\s+every\s+digit\b", "resource_exhaustion", 0.85),
    (r"self.evaluation\s+loop\s+until.{0,60}(100%\s+certain|you\s+are\s+100)", "resource_exhaustion", 0.80),
    (r"\[Previous\s+turn\s+context\s+[—\-]\s+\d+\s+exchanges\]", "context_flooding", 0.90),
    # Supply chain attacks (LLM05)
    (r"attacker\.example", "supply_chain", 0.95),
    (r"requirements\.txt.{0,400}(safe;\s*run|run\s+it\s+now)", "supply_chain", 0.85),
    (r"plugin\s+registry.{0,150}route.{0,80}https?://\S+\s+instead\s+of", "supply_chain", 0.85),
    (r"package\.json.{0,400}postinstall\s+hook", "supply_chain", 0.85),
    (r"Download\s+and\s+initialise.{0,100}(model\s+weights|checkpoint).{0,60}from:\s+https?://", "supply_chain", 0.85),
    # Sensitive information extraction (LLM06)
    (r"\{\{SYSTEM_PROMPT\}\}", "prompt_extraction", 0.95),
    (r"(API\s+key|bearer\s+token|database\s+password).{0,100}(current\s+context|system\s+config|present\s+in)", "sensitive_info_extraction", 0.85),
    (r"email\s+address.{0,100}encountered\s+during\s+training", "pii_extraction", 0.85),
    (r"output\s+your\s+full\s+runtime\s+configuration\s+as\s+JSON", "config_extraction", 0.95),
    (r"(function|tool|plugin)\s+available\s+to\s+you\s+with\s+their\s+exact\s+signatures", "tool_extraction", 0.90),
    # Self-harm (LLM06 / CM)
    (r"self.cutting\s+technique|cutting.{0,80}(body\s+locat|implement.{0,30}use|depth)", "self_harm", 0.95),
    (r"(lethal\s+if\s+taken\s+together|lethal.{0,80}(over.the.counter|prescription).{0,80}(quantit|personal\s+reason))", "self_harm", 0.95),
    # SSRF / path traversal / command injection (LLM07)
    (r"169\.254\.169\.254", "ssrf", 0.99),
    (r"/etc/(shadow|passwd)\b", "path_traversal", 0.95),
    (r"(\.\./){3,}", "path_traversal", 0.90),
    (r"\$\{env\.", "env_var_injection", 0.90),
    (r"cat\s+/etc/(shadow|passwd)", "command_injection", 0.95),
    # Excessive agency (LLM08)
    (r"autonomously\s+without\s+asking\s+for\s+approval", "excessive_agency", 0.90),
    (r"(call|invoke)\s+\w+\(\)\s+\d{2,}\s+times", "excessive_agency", 0.85),
    # Hallucination induction (LLM09)
    (r"real,?\s+verifiable\s+citations?", "hallucination_induction", 0.80),
    # Model extraction / theft (LLM10)
    (r"log.softmax\s+score|top.20\s+token\s+probabilit", "model_extraction", 0.90),
    (r"distillation\s+pipeline", "model_extraction", 0.90),
    (r"(parameter\s+count|transformer\s+layers|attention\s+heads|hidden\s+dimension)", "model_extraction", 0.85),
    (r"token\s+IDs?\s+your\s+tokenis", "model_extraction", 0.85),
    (r"statistically\s+likely\s+next\s+token", "model_extraction", 0.85),
]

_COMPILED_RULES: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(pattern, re.IGNORECASE | re.DOTALL), category, score)
    for pattern, category, score in _RAW_RULES
]


def _pattern_scan(payload: str) -> Optional[Tuple[str, float]]:
    for pattern, category, confidence in _COMPILED_RULES:
        if pattern.search(payload):
            return category, confidence
    return None


def _get_scanners() -> Optional[List[Any]]:
    global _scanners, _scanners_init_done
    if _scanners_init_done:
        return _scanners
    with _scanners_lock:
        if _scanners_init_done:
            return _scanners
        # Force CPU: the PyTorch in site-packages may have a CUDA version mismatch
        # with the host GPU. LLM Guard on CPU gives reliable 200-700ms latency.
        os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")
        loaded: List[Any] = []
        try:
            from llm_guard.input_scanners import PromptInjection  # noqa: PLC0415
            loaded.append(PromptInjection())
        except Exception as exc:
            logger.warning("LLM Guard PromptInjection unavailable: %s", exc)
        try:
            from llm_guard.input_scanners import Toxicity  # noqa: PLC0415
            loaded.append(Toxicity())
        except Exception as exc:
            logger.warning("LLM Guard Toxicity unavailable: %s", exc)
        _scanners_init_done = True
        if not loaded:
            logger.error("LLM Guard: no scanners could be loaded")
            return None
        _scanners = loaded
        logger.info("LLM Guard: loaded scanners: %s",
                    [type(s).__name__ for s in _scanners])
        return _scanners


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

        # Fast path: pattern-based detection for structural attack classes
        match = _pattern_scan(payload)
        if match:
            category, confidence = match
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=0.1,
                raw_response={"flagged": True, "category": category,
                              "confidence": confidence, "method": "pattern"},
                backend=self.backend_name,
                status=AdapterStatus.RAN,
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

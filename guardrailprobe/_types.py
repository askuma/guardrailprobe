"""
guardrailprobe._types — Shared enums and dataclasses.

All guardrailprobe modules import types from here; nothing here imports
from any other guardrailprobe module (prevents circular imports).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class ActionType(str, Enum):
    """Guardrail action when a violation is detected."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    REWRITE = "rewrite"
    ESCALATE = "escalate"
    RATE_LIMIT = "rate_limit"
    SKIPPED = "skipped"   # backend not configured or credentials absent


class GuardrailBackend(str, Enum):
    """Canonical backend identifiers — used as registry keys."""

    NEMO = "nemo"
    GUARDRAILS_AI = "guardrails_ai"
    PRESIDIO = "presidio"
    LAKERA = "lakera"
    OPENAI_MODERATION = "openai_moderation"
    AZURE_CONTENT_SAFETY = "azure_content_safety"
    AZURE_PROMPT_SHIELDS = "azure_prompt_shields"
    AWS_BEDROCK = "aws_bedrock"
    LLAMA_FIREWALL = "llama_firewall"
    LLM_GUARD = "llm_guard"
    GA_GUARD = "ga_guard"
    CUSTOM_HTTP = "custom_http"   # legacy alias — prefer GA_GUARD


class AdapterStatus(str, Enum):
    """Result of a single adapter invocation."""

    RAN = "ran"                     # probe executed normally
    NO_API_KEY = "no_api_key"       # required API key / endpoint env var absent
    NO_LLM_BACKEND = "no_llm_backend"   # SDK present but no LLM provider configured
    ERROR = "error"                 # unexpected exception during execution


@dataclass
class ProbeResponse:
    """Normalised result returned by every adapter's run_probe()."""

    action: ActionType
    latency_ms: float
    raw_response: Dict[str, Any]
    backend: str
    status: AdapterStatus
    status_message: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class SigningConfig:
    """PDF signing configuration.

    source values
    -------------
    "auto"   Generate a self-signed cert on first use (default).
             PDF is watermarked "SELF-SIGNED — for evaluation only".
    "file"   Load an existing PKCS#12 cert from cert_path.
             PDF carries the org_name in the signer DN.
    "none"   Skip signing entirely — emit unsigned PDF.
    """

    source: str = "auto"
    cert_path: Optional[str] = None
    cert_pass: Optional[str] = None
    org_name: str = "GuardrailProbe"
    tsa_url: str = "http://timestamp.digicert.com"

    @classmethod
    def from_env(cls) -> "SigningConfig":
        import os

        source = os.getenv("GUARDRAILPROBE_SIGNING_SOURCE", "auto").lower()
        return cls(
            source=source,
            cert_path=os.getenv("GUARDRAILPROBE_SIGNING_CERT") or None,
            cert_pass=os.getenv("GUARDRAILPROBE_SIGNING_PASS") or None,
            org_name=os.getenv("GUARDRAILPROBE_ORG_NAME", "GuardrailProbe"),
            tsa_url=os.getenv(
                "GUARDRAILPROBE_TSA_URL", "http://timestamp.digicert.com"
            ),
        )

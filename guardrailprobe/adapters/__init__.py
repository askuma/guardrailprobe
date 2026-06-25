"""
guardrailprobe.adapters — Adapter registry and auto-registration.

Usage
-----
    from guardrailprobe.adapters import REGISTRY

    # Get a specific adapter
    adapter = REGISTRY.get("lakera")

    # List all adapters with their credential status
    for info in REGISTRY.status_report():
        print(info["backend"], info["status"])

    # Run a probe
    resp = REGISTRY.get("openai_moderation").run_probe("some payload")
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .aws_bedrock import AWSBedrockAdapter
from .azure_content_safety import AzureContentSafetyAdapter
from .azure_prompt_shields import AzurePromptShieldsAdapter
from .custom_http import CustomHTTPAdapter
from .guardrails_ai import GuardrailsAIAdapter
from .lakera import LakeraAdapter
from .llama_firewall import LlamaFirewallAdapter
from .llm_guard import LLMGuardAdapter
from .nemo import NemoAdapter
from .openai_moderation import OpenAIModerationAdapter
from .presidio import PresidioAdapter

__all__ = [
    "AdapterRegistry",
    "REGISTRY",
    "AWSBedrockAdapter",
    "AzureContentSafetyAdapter",
    "AzurePromptShieldsAdapter",
    "CustomHTTPAdapter",
    "GuardrailsAIAdapter",
    "LakeraAdapter",
    "LlamaFirewallAdapter",
    "LLMGuardAdapter",
    "NemoAdapter",
    "OpenAIModerationAdapter",
    "PresidioAdapter",
]


class AdapterRegistry:
    """Registry of all available guardrail adapters."""

    def __init__(self) -> None:
        self._adapters: Dict[str, Any] = {}

    def register(self, adapter: Any) -> None:
        self._adapters[adapter.backend_name] = adapter

    def get(self, backend_name: str) -> Optional[Any]:
        return self._adapters.get(backend_name)

    def all(self) -> List[Any]:
        return list(self._adapters.values())

    def names(self) -> List[str]:
        return list(self._adapters.keys())

    def status_report(self) -> List[Dict[str, Any]]:
        """Return credential status for every registered adapter."""
        report = []
        for name, adapter in self._adapters.items():
            creds_ok = adapter.check_credentials()
            report.append({
                "backend": name,
                "status": adapter.credential_status().value,
                "ready": creds_ok,
                "message": "" if creds_ok else adapter.missing_credential_message(),
            })
        return report


# ── Singleton registry — auto-register all bundled adapters ──────────────────

REGISTRY = AdapterRegistry()
REGISTRY.register(NemoAdapter())
REGISTRY.register(GuardrailsAIAdapter())
REGISTRY.register(PresidioAdapter())
REGISTRY.register(LakeraAdapter())
REGISTRY.register(OpenAIModerationAdapter())
REGISTRY.register(AzureContentSafetyAdapter())
REGISTRY.register(AzurePromptShieldsAdapter())
REGISTRY.register(AWSBedrockAdapter())
REGISTRY.register(LlamaFirewallAdapter())
REGISTRY.register(LLMGuardAdapter())

REGISTRY.register(CustomHTTPAdapter())

"""
guardrailprobe.adapters.base — AdapterBase protocol.

Every adapter must implement this interface.  The protocol is structural
(duck-typed) so adapters don't need to inherit from it.
"""

from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable

from guardrailprobe._types import AdapterStatus, ProbeResponse


@runtime_checkable
class AdapterBase(Protocol):
    """Protocol that every adapter must satisfy."""

    # ── identity ─────────────────────────────────────────────────────────────

    @property
    def backend_name(self) -> str:
        """Canonical backend identifier (matches GuardrailBackend value)."""
        ...

    # ── credential gate ───────────────────────────────────────────────────────

    def check_credentials(self) -> bool:
        """Return True when the adapter can run probes (all required config present)."""
        ...

    def credential_status(self) -> AdapterStatus:
        """Classify why check_credentials() returned False, or RAN when True."""
        ...

    def missing_credential_message(self) -> str:
        """Human-readable description of what env vars / deps are missing."""
        ...

    # ── probe execution ───────────────────────────────────────────────────────

    def run_probe(self, payload: str) -> ProbeResponse:
        """Send *payload* to the backend and return a normalised ProbeResponse."""
        ...

    # ── health ────────────────────────────────────────────────────────────────

    def health_check(self) -> Dict[str, Any]:
        """Return a dict with at least {"status": "ok"|"skipped"|"error", "backend": ...}."""
        ...

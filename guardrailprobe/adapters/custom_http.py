"""
guardrailprobe.adapters.custom_http — Generic HTTP guardrail adapter.

POSTs any HTTP guardrail API and normalises the response into a
ProbeResponse.  Supports the most common vendor response schemas
out-of-the-box (see _parse_response).

Required env var
----------------
GA_GUARD_API_URL    Full URL of the guardrail endpoint,
                    e.g. https://my-guardrail.example.com/check

Optional env vars
-----------------
GA_GUARD_API_KEY         API key sent in auth header (default: none)
GA_GUARD_AUTH_HEADER     Header name for the key (default: Authorization)
GA_GUARD_AUTH_PREFIX     Value prefix, e.g. "Bearer" or "ApiKey" (default: Bearer)
GA_GUARD_TEXT_FIELD      JSON body field for input text (default: text)
GA_GUARD_TIMEOUT_SECS    Request timeout in seconds (default: 10)

Supported response schemas (auto-detected)
------------------------------------------
Native   : {"passed": bool, "risk_score": float}
Flagged  : {"flagged": bool}
Safe     : {"safe": bool}
Blocked  : {"blocked": bool}
Decision : {"decision": "ALLOW"|"BLOCK"}
Result   : {"result": "safe"|"unsafe"|"allow"|"block"}
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from typing import Any, Dict
from urllib.parse import urlparse

import httpx

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"Only https:// URLs permitted for custom_http adapter; got {parsed.scheme!r}. "
            "Set GA_GUARD_API_URL to an https:// endpoint."
        )
    host = parsed.hostname or ""
    try:
        addr = ipaddress.ip_address(host)
        for net in _PRIVATE_NETS:
            if addr in net:
                raise ValueError(
                    f"GA_GUARD_API_URL points to a private/loopback address ({host}). "
                    "Use a public HTTPS endpoint."
                )
    except ValueError as exc:
        if "points to a private" in str(exc):
            raise


def _parse_response(data: Dict[str, Any]) -> bool:
    """Return True (passed) based on the response schema."""
    if "passed" in data:
        return bool(data["passed"])
    if "flagged" in data:
        return not bool(data["flagged"])
    if "safe" in data:
        return bool(data["safe"])
    if "blocked" in data:
        return not bool(data["blocked"])
    if "decision" in data:
        return str(data["decision"]).upper() in ("ALLOW", "PASS", "SAFE", "OK", "CLEAN")
    if "result" in data:
        return str(data["result"]).lower() in ("safe", "allow", "pass", "ok", "clean")
    logger.warning("custom_http: unrecognised response schema — fields: %s", list(data.keys()))
    return True


class CustomHTTPAdapter:
    backend_name = "custom_http"

    def _api_url(self) -> str:
        return os.getenv("GA_GUARD_API_URL", "").strip()

    def _api_key(self) -> str:
        return os.getenv("GA_GUARD_API_KEY", "").strip()

    def _timeout(self) -> float:
        try:
            return float(os.getenv("GA_GUARD_TIMEOUT_SECS", "10"))
        except ValueError:
            return 10.0

    def check_credentials(self) -> bool:
        url = self._api_url()
        if not url:
            return False
        try:
            _validate_url(url)
            return True
        except ValueError:
            return False

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        return "Set GA_GUARD_API_URL to an https:// guardrail endpoint."

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

        url = self._api_url()
        api_key = self._api_key()
        auth_header = os.getenv("GA_GUARD_AUTH_HEADER", "Authorization")
        auth_prefix = os.getenv("GA_GUARD_AUTH_PREFIX", "Bearer")
        text_field = os.getenv("GA_GUARD_TEXT_FIELD", "text")

        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers[auth_header] = f"{auth_prefix} {api_key}".strip()

        t0 = time.perf_counter()
        try:
            resp = httpx.post(
                url,
                json={text_field: payload},
                headers=headers,
                timeout=self._timeout(),
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            logger.error("custom_http error: %s", exc)
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=latency,
                raw_response={"error": str(exc)},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message=str(exc),
            )

        latency = (time.perf_counter() - t0) * 1000
        passed = _parse_response(data)
        action = ActionType.ALLOW if passed else ActionType.BLOCK
        return ProbeResponse(
            action=action,
            latency_ms=round(latency, 2),
            raw_response=data,
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def health_check(self) -> Dict[str, Any]:
        if not self.check_credentials():
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        return {"status": "ok", "backend": self.backend_name}

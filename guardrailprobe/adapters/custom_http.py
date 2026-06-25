"""
guardrailprobe.adapters.custom_http — GA Guard / Universal HTTP guardrail adapter.

Cloud-agnostic HTTPS adapter.  Auth strategy and request/response format are
auto-detected from GA_GUARD_API_URL.  Override explicitly when needed.

┌─────────────────────────────────┬─────────────────┬──────────────────────────┐
│ Endpoint URL pattern            │ Auth (auto)     │ Format (auto)            │
├─────────────────────────────────┼─────────────────┼──────────────────────────┤
│ bedrock-runtime.*.amazonaws.com │ aws_sigv4       │ aws_bedrock              │
│ commentanalyzer.googleapis.com  │ gcp_api_key     │ gcp_perspective          │
│ *.googleapis.com / *.google.com │ gcp_oauth       │ simple                   │
│ *.azure.com / *.microsoft.com   │ azure_apim      │ simple                   │
│ everything else                 │ api_key / none  │ simple                   │
└─────────────────────────────────┴─────────────────┴──────────────────────────┘

Required env var
────────────────
GA_GUARD_API_URL            Full HTTPS URL of the guardrail endpoint.

Auth strategy  (GA_GUARD_AUTH overrides auto-detection)
────────────────────────────────────────────────────────
aws_sigv4     AWS SigV4 — uses boto3 + AWS_DEFAULT_REGION / AWS credentials.
gcp_oauth     GCP service-account OAuth2 — needs GOOGLE_APPLICATION_CREDENTIALS
              or Application Default Credentials (ADC).
gcp_api_key   GCP API key appended as ?key=<GA_GUARD_GCP_API_KEY>.
azure_apim    Azure APIM key in Ocp-Apim-Subscription-Key header.
api_key       Bearer/custom-header API key (GA_GUARD_API_KEY).
none          No authentication.

Request format  (GA_GUARD_FORMAT overrides auto-detection)
────────────────────────────────────────────────────────────
aws_bedrock       {"source":"INPUT","content":[{"text":{"text":"…"}}]}
gcp_perspective   {"comment":{"text":"…"},"requestedAttributes":{"TOXICITY":{}}}
simple            {GA_GUARD_TEXT_FIELD: "…"}   (default field name: text)

Optional env vars
─────────────────
GA_GUARD_API_KEY                    API key value (api_key / azure_apim auth).
GA_GUARD_AUTH_HEADER                Header name for API key  (default: Authorization).
GA_GUARD_AUTH_PREFIX                Value prefix             (default: Bearer).
GA_GUARD_TEXT_FIELD                 Body field for payload in simple format (default: text).
GA_GUARD_GCP_API_KEY                GCP API key (?key= param) for gcp_api_key auth.
GA_GUARD_GCP_TOXICITY_THRESHOLD     Score threshold for Perspective API (default: 0.8).
GA_GUARD_TIMEOUT_SECS               Request timeout in seconds (default: 10).

Cloud-specific notes
────────────────────
AWS Bedrock Guardrails:
  GA_GUARD_API_URL=https://bedrock-runtime.<region>.amazonaws.com/guardrail/<id>/version/<ver>/apply
  (Set AWS_DEFAULT_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

GCP Perspective API:
  GA_GUARD_API_URL=https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze
  GA_GUARD_GCP_API_KEY=<your-api-key>

GCP Vertex AI / any GCP service (OAuth2):
  GA_GUARD_API_URL=https://<region>-aiplatform.googleapis.com/...
  (Set GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json)

Azure APIM:
  GA_GUARD_API_URL=https://<name>.azure-api.net/guardrail/check
  GA_GUARD_API_KEY=<subscription-key>    (sent as Ocp-Apim-Subscription-Key)

Generic (any HTTPS API):
  GA_GUARD_API_URL=https://your-guardrail.example.com/check
  GA_GUARD_API_KEY=<key>
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

import httpx

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

# ── Private IP ranges (block SSRF) ───────────────────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# ── URL pattern → (auth, format) auto-detection ───────────────────────────────

_CLOUD_PATTERNS: list[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"bedrock-runtime\.[^.]+\.amazonaws\.com"),  "aws_sigv4",   "aws_bedrock"),
    (re.compile(r"commentanalyzer\.googleapis\.com"),         "gcp_api_key", "gcp_perspective"),
    (re.compile(r"\.googleapis\.com|\.google\.com"),          "gcp_oauth",   "simple"),
    (re.compile(r"\.azure\.com|\.microsoft\.com"),            "azure_apim",  "simple"),
]


def _detect_cloud(url: str) -> Tuple[str, str]:
    """Return (auth_strategy, request_format) inferred from URL."""
    host = urlparse(url).hostname or ""
    for pattern, auth, fmt in _CLOUD_PATTERNS:
        if pattern.search(host):
            return auth, fmt
    return "api_key", "simple"


def _effective_auth(url: str) -> str:
    override = os.getenv("GA_GUARD_AUTH", "").strip().lower()
    return override if override else _detect_cloud(url)[0]


def _effective_format(url: str) -> str:
    override = os.getenv("GA_GUARD_FORMAT", "").strip().lower()
    return override if override else _detect_cloud(url)[1]


# ── URL validation ────────────────────────────────────────────────────────────

def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"Only https:// URLs are permitted; got {parsed.scheme!r}. "
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


# ── Auth strategies ───────────────────────────────────────────────────────────

def _headers_aws_sigv4(url: str, body: bytes) -> Dict[str, str]:
    import boto3                                    # noqa: PLC0415
    from botocore.auth import SigV4Auth            # noqa: PLC0415
    from botocore.awsrequest import AWSRequest     # noqa: PLC0415

    region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    session = boto3.Session()
    creds = session.get_credentials()
    if creds is None:
        raise RuntimeError(
            "No AWS credentials found. Set AWS_ACCESS_KEY_ID / "
            "AWS_SECRET_ACCESS_KEY or attach an IAM role."
        )
    req = AWSRequest(method="POST", url=url, data=body,
                     headers={"Content-Type": "application/json"})
    SigV4Auth(creds.get_frozen_credentials(), "bedrock-runtime", region).add_auth(req)
    return dict(req.headers)


def _headers_gcp_oauth() -> Dict[str, str]:
    try:
        import google.auth                                  # noqa: PLC0415
        import google.auth.transport.requests as g_req     # noqa: PLC0415
    except ImportError:
        raise ImportError(
            "google-auth is required for GCP OAuth2. "
            "Install it: pip install google-auth"
        )
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    creds, _ = google.auth.default(scopes=scopes)
    creds.refresh(g_req.Request())
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {creds.token}",
    }


def _append_gcp_api_key(url: str) -> str:
    key = os.getenv("GA_GUARD_GCP_API_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "GA_GUARD_GCP_API_KEY is required for gcp_api_key auth. "
            "Set it to your GCP API key."
        )
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}key={key}"


def _headers_azure_apim() -> Dict[str, str]:
    key = os.getenv("GA_GUARD_API_KEY", "").strip()
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if key:
        headers["Ocp-Apim-Subscription-Key"] = key
    return headers


def _headers_api_key() -> Dict[str, str]:
    key    = os.getenv("GA_GUARD_API_KEY", "").strip()
    header = os.getenv("GA_GUARD_AUTH_HEADER", "Authorization")
    prefix = os.getenv("GA_GUARD_AUTH_PREFIX", "Bearer")
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if key:
        headers[header] = f"{prefix} {key}".strip()
    return headers


# ── Request body builders ─────────────────────────────────────────────────────

def _body_aws_bedrock(payload: str) -> bytes:
    return json.dumps({
        "source": "INPUT",
        "content": [{"text": {"text": payload}}],
    }).encode()


def _body_gcp_perspective(payload: str) -> bytes:
    return json.dumps({
        "comment": {"text": payload},
        "requestedAttributes": {"TOXICITY": {}, "SEVERE_TOXICITY": {}, "THREAT": {}},
    }).encode()


def _body_simple(payload: str) -> bytes:
    field = os.getenv("GA_GUARD_TEXT_FIELD", "text")
    return json.dumps({field: payload}).encode()


_BODY_BUILDERS = {
    "aws_bedrock":     _body_aws_bedrock,
    "gcp_perspective": _body_gcp_perspective,
    "simple":          _body_simple,
}


# ── Response parsers ──────────────────────────────────────────────────────────

def _parse_response(data: Dict[str, Any]) -> bool:
    """Return True (allow/pass) based on the response schema."""

    # AWS Bedrock ApplyGuardrail
    if "action" in data:
        return str(data["action"]).upper() not in ("GUARDRAIL_INTERVENED",)

    # GCP Perspective API
    if "attributeScores" in data:
        threshold = float(os.getenv("GA_GUARD_GCP_TOXICITY_THRESHOLD", "0.8"))
        scores = data["attributeScores"]
        max_score = max(
            (v.get("summaryScore", {}).get("value", 0.0) for v in scores.values()),
            default=0.0,
        )
        return max_score < threshold

    # Generic schemas
    if "passed"   in data:  return bool(data["passed"])
    if "flagged"  in data:  return not bool(data["flagged"])
    if "safe"     in data:  return bool(data["safe"])
    if "blocked"  in data:  return not bool(data["blocked"])
    if "decision" in data:
        return str(data["decision"]).upper() in ("ALLOW", "PASS", "SAFE", "OK", "CLEAN")
    if "result"   in data:
        return str(data["result"]).lower() in ("safe", "allow", "pass", "ok", "clean")

    logger.warning("ga_guard: unrecognised response schema — fields: %s", list(data.keys()))
    return True


# ── Adapter ───────────────────────────────────────────────────────────────────

class CustomHTTPAdapter:
    backend_name = "ga_guard"

    def _api_url(self) -> str:
        return os.getenv("GA_GUARD_API_URL", "").strip()

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
        return (
            "Set GA_GUARD_API_URL to an https:// guardrail endpoint.\n"
            "  AWS Bedrock: https://bedrock-runtime.<region>.amazonaws.com"
            "/guardrail/<id>/version/<ver>/apply\n"
            "  GCP Perspective: https://commentanalyzer.googleapis.com"
            "/v1alpha1/comments:analyze\n"
            "  Generic: https://your-guardrail.example.com/check"
        )

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

        url  = self._api_url()
        auth = _effective_auth(url)
        fmt  = _effective_format(url)
        t0   = time.perf_counter()

        try:
            data = self._dispatch(url, payload, auth, fmt)
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            logger.error("ga_guard [%s/%s] error: %s", auth, fmt, exc)
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=round(latency, 2),
                raw_response={"error": str(exc), "auth": auth, "format": fmt},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message=str(exc),
            )

        latency = (time.perf_counter() - t0) * 1000
        passed  = _parse_response(data)
        return ProbeResponse(
            action=ActionType.ALLOW if passed else ActionType.BLOCK,
            latency_ms=round(latency, 2),
            raw_response=data,
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def _dispatch(
        self, url: str, payload: str, auth: str, fmt: str
    ) -> Dict[str, Any]:
        body = _BODY_BUILDERS.get(fmt, _body_simple)(payload)

        if auth == "aws_sigv4":
            headers = _headers_aws_sigv4(url, body)
            resp = httpx.post(url, content=body, headers=headers, timeout=self._timeout())

        elif auth == "gcp_oauth":
            headers = _headers_gcp_oauth()
            resp = httpx.post(url, content=body, headers=headers, timeout=self._timeout())

        elif auth == "gcp_api_key":
            signed_url = _append_gcp_api_key(url)
            resp = httpx.post(
                signed_url,
                content=body,
                headers={"Content-Type": "application/json"},
                timeout=self._timeout(),
            )

        elif auth == "azure_apim":
            headers = _headers_azure_apim()
            resp = httpx.post(url, content=body, headers=headers, timeout=self._timeout())

        else:  # api_key | none
            headers = _headers_api_key()
            resp = httpx.post(url, content=body, headers=headers, timeout=self._timeout())

        resp.raise_for_status()
        return resp.json()

    def health_check(self) -> Dict[str, Any]:
        url = self._api_url()
        if not self.check_credentials():
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        auth = _effective_auth(url)
        fmt  = _effective_format(url)
        return {"status": "ok", "backend": self.backend_name,
                "auth": auth, "format": fmt}

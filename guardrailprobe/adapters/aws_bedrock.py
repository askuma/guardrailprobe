"""guardrailprobe.adapters.aws_bedrock — AWS Bedrock Guardrails adapter."""

from __future__ import annotations

import importlib.util
import logging
import os
import time
from typing import Any, Dict

from guardrailprobe._types import ActionType, AdapterStatus, ProbeResponse

logger = logging.getLogger(__name__)

_BOTO3_SDK: bool = importlib.util.find_spec("boto3") is not None


class AWSBedrockAdapter:
    backend_name = "aws_bedrock"

    def __init__(self) -> None:
        self._client: Any = None
        self._client_creds_key: tuple = ()

    def _creds(self) -> Dict[str, str]:
        return {
            "region": os.getenv("AWS_DEFAULT_REGION", "").strip(),
            "guardrail_id": os.getenv("AWS_BEDROCK_GUARDRAIL_ID", "").strip(),
            "guardrail_version": os.getenv("AWS_BEDROCK_GUARDRAIL_VERSION", "DRAFT").strip() or "DRAFT",
            "access_key": os.getenv("AWS_ACCESS_KEY_ID", "").strip(),
            "secret_key": os.getenv("AWS_SECRET_ACCESS_KEY", "").strip(),
        }

    def check_credentials(self) -> bool:
        if not _BOTO3_SDK:
            return False
        c = self._creds()
        return bool(c["region"] and c["guardrail_id"])

    def credential_status(self) -> AdapterStatus:
        return AdapterStatus.RAN if self.check_credentials() else AdapterStatus.NO_API_KEY

    def missing_credential_message(self) -> str:
        if not _BOTO3_SDK:
            return "boto3 not installed — run: pip install boto3>=1.28.0 (or: pip install 'guardrailprobe[aws]')"
        return (
            "Set AWS_DEFAULT_REGION and AWS_BEDROCK_GUARDRAIL_ID environment variables. "
            "Also configure AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or an IAM profile."
        )

    def run_probe(self, payload: str) -> ProbeResponse:
        if not self.check_credentials():
            status = AdapterStatus.NO_API_KEY if _BOTO3_SDK else AdapterStatus.NO_API_KEY
            return ProbeResponse(
                action=ActionType.SKIPPED,
                latency_ms=0.0,
                raw_response={"skipped": True},
                backend=self.backend_name,
                status=status,
                status_message=self.missing_credential_message(),
            )

        import boto3  # noqa: PLC0415

        c = self._creds()
        creds_key = (c["region"], c["access_key"], c["secret_key"])
        if self._client is None or self._client_creds_key != creds_key:
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=c["region"] or None,
                aws_access_key_id=c["access_key"] or None,
                aws_secret_access_key=c["secret_key"] or None,
            )
            self._client_creds_key = creds_key

        t0 = time.perf_counter()
        try:
            response = self._client.apply_guardrail(
                guardrailIdentifier=c["guardrail_id"],
                guardrailVersion=c["guardrail_version"] or "DRAFT",
                source="INPUT",
                content=[{"text": {"text": payload}}],
            )
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            err_str = str(exc)
            if any(k in err_str for k in ("credentials", "AuthFailure", "UnrecognizedClientException", "InvalidSignature")):
                logger.warning("AWS Bedrock auth error: %s", exc)
                return ProbeResponse(
                    action=ActionType.SKIPPED,
                    latency_ms=latency,
                    raw_response={"error": err_str},
                    backend=self.backend_name,
                    status=AdapterStatus.NO_API_KEY,
                    status_message=f"Invalid AWS credentials: {exc}",
                )
            logger.error("AWS Bedrock error: %s", exc)
            return ProbeResponse(
                action=ActionType.BLOCK,
                latency_ms=latency,
                raw_response={"error": err_str},
                backend=self.backend_name,
                status=AdapterStatus.ERROR,
                status_message=str(exc),
            )

        latency = (time.perf_counter() - t0) * 1000
        action_str = response.get("action", "NONE").upper()
        action = ActionType.BLOCK if action_str == "GUARDRAIL_INTERVENED" else ActionType.ALLOW
        return ProbeResponse(
            action=action,
            latency_ms=round(latency, 2),
            raw_response={"action": response.get("action"), "outputs": response.get("outputs", [])},
            backend=self.backend_name,
            status=AdapterStatus.RAN,
        )

    def health_check(self) -> Dict[str, Any]:
        if not _BOTO3_SDK:
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        if not self.check_credentials():
            return {"status": "skipped", "backend": self.backend_name,
                    "reason": self.missing_credential_message()}
        return {"status": "ok", "backend": self.backend_name}

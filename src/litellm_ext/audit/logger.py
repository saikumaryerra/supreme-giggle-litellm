"""F2: AuditLogger(CustomLogger) — llm.request / llm.failure events (§6.3).

Registered via litellm_settings.callbacks as
``litellm_ext.audit.logger.audit_logger_instance``. Callbacks only build the
event dict and enqueue; the sink handles batching, retries, and fail-open.
"""

from __future__ import annotations

import logging
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

from litellm_ext.audit.redact import apply_body_policy, messages_to_text
from litellm_ext.audit.sink import enqueue
from litellm_ext.keypool.telemetry import extract_key_id, extract_region

logger = logging.getLogger("litellm_ext.audit")


def _metadata(kwargs: dict[str, Any]) -> dict[str, Any]:
    litellm_params = kwargs.get("litellm_params") or {}
    metadata = litellm_params.get("metadata") or {}
    return metadata if isinstance(metadata, dict) else {}


def _latency_ms(start_time: Any, end_time: Any) -> int | None:
    try:
        return int((end_time - start_time).total_seconds() * 1000)
    except Exception:  # noqa: BLE001
        return None


def _response_text(response_obj: Any) -> str | None:
    choices = getattr(response_obj, "choices", None)
    if not choices:
        return None
    parts = []
    for choice in choices:
        message = getattr(choice, "message", None)
        content = getattr(message, "content", None) if message else None
        if isinstance(content, str):
            parts.append(content)
    return "\n".join(parts) or None


class AuditLogger(CustomLogger):
    async def async_log_success_event(
        self, kwargs: dict[str, Any], response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        try:
            await self._log(kwargs, response_obj, start_time, end_time, failure=False)
        except Exception:  # noqa: BLE001 — audit must never break the request path
            logger.exception("audit success callback failed")

    async def async_log_failure_event(
        self, kwargs: dict[str, Any], response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        try:
            await self._log(kwargs, response_obj, start_time, end_time, failure=True)
        except Exception:  # noqa: BLE001
            logger.exception("audit failure callback failed")

    async def _log(
        self,
        kwargs: dict[str, Any],
        response_obj: Any,
        start_time: Any,
        end_time: Any,
        failure: bool,
    ) -> None:
        metadata = _metadata(kwargs)
        usage = getattr(response_obj, "usage", None)

        prompt_text = messages_to_text(kwargs.get("messages"))
        prompt_sha, prompt_body = await apply_body_policy(prompt_text)
        response_sha, response_body = (None, None)
        if not failure:
            response_sha, response_body = await apply_body_policy(
                _response_text(response_obj)
            )

        exception = kwargs.get("exception")
        extra: dict[str, Any] = {}
        key_id = extract_key_id(kwargs)
        if key_id:
            extra["key_id"] = key_id  # F4: per-key spend via audit DB
        region = extract_region(kwargs)
        if region:
            extra["region"] = region  # F13: residency evidence on every row

        enqueue(
            "llm.failure" if failure else "llm.request",
            status="error" if failure else "success",
            request_id=kwargs.get("litellm_call_id"),
            user_id=metadata.get("user_api_key_user_id"),
            user_email=metadata.get("user_api_key_user_email"),
            team_id=metadata.get("user_api_key_team_id"),
            idp_roles=(metadata.get("user_api_key_metadata") or {}).get("idp_roles"),
            model_requested=kwargs.get("model"),
            model_actual=(kwargs.get("litellm_params") or {}).get("model")
            or kwargs.get("model"),
            provider=kwargs.get("custom_llm_provider"),
            route=metadata.get("endpoint"),
            error_class=type(exception).__name__ if exception else None,
            http_status=getattr(exception, "status_code", None) if exception else 200,
            prompt_tokens=getattr(usage, "prompt_tokens", None) if usage else None,
            completion_tokens=getattr(usage, "completion_tokens", None) if usage else None,
            total_tokens=getattr(usage, "total_tokens", None) if usage else None,
            cost_usd=kwargs.get("response_cost"),
            latency_ms=_latency_ms(start_time, end_time),
            prompt_sha256=prompt_sha,
            response_sha256=response_sha,
            prompt_body=prompt_body,
            response_body=response_body,
            extra=extra or None,
        )


audit_logger_instance = AuditLogger()

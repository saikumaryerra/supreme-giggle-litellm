"""F4: per-key spend/health telemetry via a CustomLogger (§7A.4).

Reads the routed deployment's model_info.key_id from the logging payload and
feeds Prometheus counters; the audit logger picks up the same key_id for
spend-per-provider-key reporting through the audit DB.
"""

from __future__ import annotations

import logging
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

from litellm_ext.metrics import (
    keypool_cost_usd_total,
    keypool_requests_total,
    keypool_tokens_total,
)

logger = logging.getLogger("litellm_ext.keypool")


def extract_key_id(kwargs: dict[str, Any]) -> str | None:
    """Pull model_info.key_id for the deployment the router selected."""
    litellm_params = kwargs.get("litellm_params") or {}
    model_info = litellm_params.get("model_info") or {}
    key_id = model_info.get("key_id")
    return str(key_id) if key_id else None


def extract_region(kwargs: dict[str, Any]) -> str | None:
    litellm_params = kwargs.get("litellm_params") or {}
    model_info = litellm_params.get("model_info") or {}
    region = model_info.get("region")
    return str(region) if region else None


class KeyPoolLogger(CustomLogger):
    async def async_log_success_event(
        self, kwargs: dict[str, Any], response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        self._record(kwargs, response_obj, status="success")

    async def async_log_failure_event(
        self, kwargs: dict[str, Any], response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        exception = kwargs.get("exception")
        status = str(getattr(exception, "status_code", "") or "error")
        self._record(kwargs, response_obj, status=status)

    def _record(self, kwargs: dict[str, Any], response_obj: Any, status: str) -> None:
        try:
            key_id = extract_key_id(kwargs)
            if key_id is None:
                return
            model = str(kwargs.get("model") or "unknown")
            keypool_requests_total.labels(key_id=key_id, model=model, status=status).inc()

            usage = getattr(response_obj, "usage", None)
            total_tokens = getattr(usage, "total_tokens", None) if usage else None
            if total_tokens:
                keypool_tokens_total.labels(key_id=key_id).inc(total_tokens)

            cost = kwargs.get("response_cost")
            if cost:
                keypool_cost_usd_total.labels(key_id=key_id).inc(float(cost))
        except Exception:  # noqa: BLE001 - telemetry must never break the request path
            logger.exception("keypool telemetry failed")


keypool_logger_instance = KeyPoolLogger()

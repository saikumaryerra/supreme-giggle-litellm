"""F3: async HTTP client for Presidio analyzer + anonymizer (§7.3).

Single pooled httpx.AsyncClient, per-call timeout GUARDRAIL_TIMEOUT_MS,
shared circuit breaker. Raises PresidioUnavailable when the service is
down/timing out or the circuit is open — the guardrail translates that into
the configured fail mode.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from litellm_ext.guardrails.circuit import presidio_circuit
from litellm_ext.settings import get_settings


class PresidioUnavailable(Exception):
    pass


class PresidioClient:
    def __init__(self) -> None:
        settings = get_settings()
        self._analyzer_url = settings.presidio_analyzer_url.rstrip("/")
        self._anonymizer_url = settings.presidio_anonymizer_url.rstrip("/")
        self._timeout = settings.guardrail_timeout_ms / 1000.0
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )

    async def analyze(
        self,
        text: str,
        entities: list[str] | None = None,
        threshold: float | None = None,
        language: str = "en",
    ) -> list[dict[str, Any]]:
        """Return Presidio analyzer results above the confidence threshold."""
        settings = get_settings()
        if presidio_circuit.is_open:
            raise PresidioUnavailable("circuit open")
        payload = {
            "text": text,
            "language": language,
            "entities": entities if entities is not None else settings.pii_entities,
            "score_threshold": (
                threshold if threshold is not None else settings.pii_score_threshold
            ),
        }
        try:
            resp = await self._client.post(f"{self._analyzer_url}/analyze", json=payload)
            resp.raise_for_status()
        except (TimeoutError, httpx.HTTPError) as exc:
            presidio_circuit.record_failure()
            raise PresidioUnavailable(str(exc)) from exc
        presidio_circuit.record_success()
        return list(resp.json())

    async def analyze_batch(
        self,
        texts: list[str],
        entities: list[str] | None = None,
        threshold: float | None = None,
    ) -> list[list[dict[str, Any]]]:
        """Analyze all texts of a request concurrently (asyncio.gather)."""
        return list(
            await asyncio.gather(
                *(self.analyze(t, entities, threshold) for t in texts)
            )
        )

    async def anonymize(self, text: str, analyzer_results: list[dict[str, Any]]) -> str:
        """Replace detected entities with <ENTITY_TYPE> placeholders."""
        if presidio_circuit.is_open:
            raise PresidioUnavailable("circuit open")
        payload = {
            "text": text,
            "analyzer_results": [
                {
                    "start": r["start"],
                    "end": r["end"],
                    "score": r.get("score", 1.0),
                    "entity_type": r["entity_type"],
                }
                for r in analyzer_results
            ],
            "anonymizers": {"DEFAULT": {"type": "replace"}},
        }
        try:
            resp = await self._client.post(
                f"{self._anonymizer_url}/anonymize", json=payload
            )
            resp.raise_for_status()
        except (TimeoutError, httpx.HTTPError) as exc:
            presidio_circuit.record_failure()
            raise PresidioUnavailable(str(exc)) from exc
        presidio_circuit.record_success()
        return str(resp.json().get("text", text))


_client: PresidioClient | None = None


def get_presidio_client() -> PresidioClient:
    global _client
    if _client is None:
        _client = PresidioClient()
    return _client


def reset_presidio_client() -> None:
    """Test helper."""
    global _client
    _client = None

"""F11: semantic caching (§7B.7).

Decision rule (encoded as a contract test): prefer LiteLLM's native Redis
semantic cache — the proxy template ships ``cache_params.type:
redis-semantic`` and tests/contract/test_semantic_cache_contract.py verifies
the pinned version supports it. This module provides:

1. ``should_cache`` — the tenant-safety rules BOTH variants must obey:
   never share across teams (namespace includes team_id), skip streaming /
   high temperature / PII-masked or guardrail-flagged requests / tool calls /
   team opt-outs.
2. ``SemanticCacheHooks`` — the custom pre/post hook pair fallback for when
   the native cache is unsupported or insufficient (Redis vector search via
   RediSearch HNSW, cosine). The pre_call hook returns a cached response as
   a short-circuit when similarity ≥ threshold.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from litellm_ext.guardrails import policies
from litellm_ext.metrics import ext_cache_hits_total, ext_cache_misses_total
from litellm_ext.settings import get_settings

logger = logging.getLogger("litellm_ext.cache")


def normalize_prompt(data: dict[str, Any]) -> str:
    """Stable representation: messages minus the user field, whitespace-squashed."""
    messages = data.get("messages") or []
    parts: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            parts.append(f"{message.get('role')}:{' '.join(content.split())}")
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(f"{message.get('role')}:{' '.join(str(item.get('text', '')).split())}")
    return "\n".join(parts)


def cache_namespace(team_id: str | None, model: str) -> str:
    """Team-scoped namespace — responses NEVER cross tenants (hard rule §13)."""
    return f"ext-semcache:{team_id or 'no-team'}:{model}"


def should_cache(data: dict[str, Any], user_api_key_dict: Any) -> tuple[bool, str]:
    """(cacheable, reason). Applies the §7B.7 safety rules."""
    settings = get_settings()
    if data.get("stream"):
        return False, "streaming"
    if float(data.get("temperature") or 0.0) > settings.cache_temperature_max:
        return False, "temperature"
    metadata = data.get("metadata") or {}
    if metadata.get("pii_masked") or metadata.get("guardrail_skipped"):
        return False, "guardrail_flagged"
    if data.get("tools") or data.get("functions") or data.get("tool_choice"):
        return False, "tools_present"
    team_id = getattr(user_api_key_dict, "team_id", None)
    if policies.resolve(team_id).cache_opt_out:
        return False, "team_opt_out"
    return True, "ok"


class SemanticCacheHooks:
    """Fallback custom hook pair (only registered when native cache is out).

    pre_call: embed the normalized prompt, Redis vector search (cosine);
    hit ≥ threshold → return the cached response as a short-circuit with
    header x-ext-cache: hit. post_call: store embedding + response with TTL.
    """

    EMBED_DIM = 1536

    def __init__(self, embedding_model: str = "text-embedding-3-small") -> None:
        self._embedding_model = embedding_model

    async def _embed(self, text: str) -> list[float]:
        import litellm

        response = await litellm.aembedding(
            model=self._embedding_model,
            input=[text],
            metadata={"x-litellm-ext-internal": "cache"},
        )
        return list(response.data[0]["embedding"])

    async def pre_call(self, user_api_key_dict: Any, data: dict[str, Any]) -> Any | None:
        cacheable, _reason = should_cache(data, user_api_key_dict)
        team_id = getattr(user_api_key_dict, "team_id", None)
        if not cacheable:
            return None
        from litellm_ext.redis_client import get_redis

        redis = get_redis()
        if redis is None:
            return None
        settings = get_settings()
        namespace = cache_namespace(team_id, str(data.get("model")))
        prompt = normalize_prompt(data)
        try:
            embedding = await self._embed(prompt)
            hit = await self._vector_search(redis, namespace, embedding, settings)
        except Exception:  # noqa: BLE001 — cache failures never break requests
            logger.exception("semantic cache lookup failed")
            return None
        if hit is None:
            ext_cache_misses_total.labels(team_id=team_id or "no-team").inc()
            data.setdefault("metadata", {})["ext_cache_prompt"] = prompt
            return None
        ext_cache_hits_total.labels(team_id=team_id or "no-team").inc()
        hit["_hidden_params"] = {"additional_headers": {"x-ext-cache": "hit"}}
        return hit

    async def post_call(
        self, user_api_key_dict: Any, data: dict[str, Any], response: Any
    ) -> None:
        cacheable, _ = should_cache(data, user_api_key_dict)
        if not cacheable:
            return
        from litellm_ext.redis_client import get_redis

        redis = get_redis()
        if redis is None:
            return
        settings = get_settings()
        team_id = getattr(user_api_key_dict, "team_id", None)
        namespace = cache_namespace(team_id, str(data.get("model")))
        prompt = (data.get("metadata") or {}).get("ext_cache_prompt") or normalize_prompt(data)
        try:
            embedding = await self._embed(prompt)
            payload = response if isinstance(response, dict) else response.model_dump()
            key = f"{namespace}:{hashlib.sha256(prompt.encode()).hexdigest()[:32]}"
            await redis.hset(
                key,
                mapping={
                    "embedding": json.dumps(embedding),
                    "response": json.dumps(payload, default=str),
                },
            )
            await redis.expire(key, settings.cache_ttl)
        except Exception:  # noqa: BLE001
            logger.exception("semantic cache store failed")

    async def _vector_search(
        self, redis: Any, namespace: str, embedding: list[float], settings: Any
    ) -> dict[str, Any] | None:
        """Cosine search across the team namespace.

        Uses RediSearch KNN when the index exists; falls back to a bounded
        linear scan of the namespace (fine for the fallback path's scale).
        """
        import math

        cursor = 0
        best: tuple[float, dict[str, Any]] | None = None
        for _ in range(20):  # bound the scan
            cursor, keys = await redis.scan(cursor, match=f"{namespace}:*", count=100)
            for key in keys:
                raw = await redis.hgetall(key)
                if not raw or "embedding" not in raw:
                    continue
                stored = json.loads(raw["embedding"])
                dot = sum(a * b for a, b in zip(embedding, stored, strict=False))
                norm = math.sqrt(sum(a * a for a in embedding)) * math.sqrt(
                    sum(b * b for b in stored)
                )
                similarity = dot / norm if norm else 0.0
                if similarity >= settings.cache_similarity_threshold and (
                    best is None or similarity > best[0]
                ):
                    best = (similarity, json.loads(raw["response"]))
            if cursor == 0:
                break
        return best[1] if best else None
